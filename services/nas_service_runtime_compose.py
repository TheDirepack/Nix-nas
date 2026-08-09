#!/usr/bin/env python3
"""Thin Podman Compose adapter for managed services.

The user-authored Compose file remains runtime authority. Managed Services V2
adds NAS-owned storage policy through a generated secondary Compose document;
it never rewrites the source Compose file.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

from nas_managed_service import ManagedServiceError

APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
OVERRIDE_ROOT = pathlib.Path("/run/nas-control/compose")


def _compose_source(service_id: str, service: dict[str, Any]) -> pathlib.Path:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "compose":
        raise ManagedServiceError(f"Service {service_id} is not a Compose service")

    source = runtime.get("source", "")
    if not isinstance(source, str) or not pathlib.PurePosixPath(source).is_absolute():
        raise ManagedServiceError(f"Compose source for {service_id} must be under {APP_ROOT / service_id}/")
    app_root = APP_ROOT.resolve()
    root = (app_root / service_id).resolve()
    path = pathlib.Path(source).resolve()
    try:
        root.relative_to(app_root)
        path.relative_to(root)
    except ValueError as exc:
        raise ManagedServiceError(f"Compose source for {service_id} must be under {root}/") from exc
    if path.suffix not in {".yaml", ".yml"}:
        raise ManagedServiceError(f"Compose source for {service_id} must be a YAML file")
    return path


def _compose_mounts(service_id: str, service: dict[str, Any]) -> dict[str, list[str]]:
    selected: dict[str, list[str]] = {}
    for mount in service.get("resolvedStorage") or []:
        if not isinstance(mount, dict) or "resource" not in mount:
            continue
        target = mount.get("target")
        if not isinstance(target, str) or not target:
            raise ManagedServiceError(
                f"Compose service {service_id}: every V2 storage attachment requires target=<compose-service>"
            )
        host = mount.get("hostPath")
        guest = mount.get("guestPath")
        mode = mount.get("mode")
        if not isinstance(host, str) or not host.startswith("/"):
            raise ManagedServiceError(f"Compose service {service_id}: resolved hostPath must be absolute")
        if not isinstance(guest, str) or not guest.startswith("/"):
            raise ManagedServiceError(f"Compose service {service_id}: resolved guestPath must be absolute")
        if mode not in {"ro", "rw"}:
            raise ManagedServiceError(f"Compose service {service_id}: resolved storage mode must be ro or rw")
        if any(char in host or char in guest for char in ("\x00", "\r", "\n", ":")):
            raise ManagedServiceError(f"Compose service {service_id}: resolved path contains an unsafe delimiter")
        selected.setdefault(target, []).append(f"{host}:{guest}:{mode}")
    return selected


def render_compose_override(service_id: str, service: dict[str, Any]) -> dict[str, Any] | None:
    mounts = _compose_mounts(service_id, service)
    if not mounts:
        return None
    return {"services": {target: {"volumes": volumes} for target, volumes in sorted(mounts.items())}}


def _override_path(service_id: str) -> pathlib.Path:
    return OVERRIDE_ROOT / f"{service_id}-v2.override.json"


def _write_override(service_id: str, service: dict[str, Any]) -> pathlib.Path | None:
    rendered = render_compose_override(service_id, service)
    path = _override_path(service_id)
    if rendered is None:
        path.unlink(missing_ok=True)
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(rendered, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def plan_compose(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "compose":
        return {"actions": [], "warnings": [f"Service {service_id} is not a Compose service"]}
    if service.get("enabled") and (service.get("lifecycle") or {}).get("mode") == "session":
        raise ManagedServiceError(
            f"Compose service {service_id}: session lifecycle requires a disposable Compose runtime implementation"
        )

    source = _compose_source(service_id, service)
    enabled = bool(service.get("enabled"))
    override = render_compose_override(service_id, service)
    override_path = str(_override_path(service_id)) if override is not None else None
    return {
        "service": service_id,
        "runtime": "podman-compose",
        "source": str(source),
        "override": override_path,
        "project": service_id,
        "enabled": enabled,
        "resolvedStorage": service.get("resolvedStorage", []),
        "actions": [{
            "type": "podman-compose",
            "operation": "up" if enabled else "down",
            "project": service_id,
            "source": str(source),
            "override": override_path,
        }],
    }


def _compose_command(plan: dict[str, Any], *, require_override_exists: bool = True) -> list[str]:
    command = ["podman", "compose", "-p", plan["project"], "-f", plan["source"]]
    override = plan.get("override")
    if override and (not require_override_exists or pathlib.Path(override).is_file()):
        command.extend(["-f", override])
    return command


def apply_compose(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_compose(service_id, service)
    if dry_run or not plan["actions"]:
        return plan

    if plan["enabled"]:
        override_path = _write_override(service_id, service)
        plan["override"] = str(override_path) if override_path is not None else None
        command = _compose_command(plan)
        command.extend(["up", "-d"])
    else:
        # A prior up may have used the generated override. Keep it in the down
        # invocation when present, but teardown must still work after /run was
        # cleared by a reboot or manual cleanup.
        command = _compose_command(plan, require_override_exists=True)
        command.extend(["down", "--remove-orphans"])
    subprocess.run(command, check=True)
    if not plan["enabled"]:
        _override_path(service_id).unlink(missing_ok=True)
    return plan


def remove_compose(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> None:
    if dry_run:
        return
    plan = plan_compose(service_id, {**service, "enabled": False})
    if not plan["actions"]:
        return
    command = _compose_command(plan, require_override_exists=True)
    command.extend(["down", "--remove-orphans"])
    subprocess.run(command, check=True)
    _override_path(service_id).unlink(missing_ok=True)
