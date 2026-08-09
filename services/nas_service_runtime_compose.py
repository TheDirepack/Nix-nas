#!/usr/bin/env python3
"""Thin Podman Compose adapter for managed services."""

from __future__ import annotations

import pathlib
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError

APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")


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


def _validate_lifecycle(service_id: str, service: dict[str, Any]) -> None:
    lifecycle = service.get("lifecycle") or {}
    if lifecycle.get("mode") == "session" and service.get("enabled"):
        raise ManagedServiceError(
            f"Service {service_id}: session lifecycle is not supported for Compose; "
            "use a dedicated disposable session runtime"
        )


def plan_compose(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "compose":
        return {
            "actions": [],
            "warnings": [f"Service {service_id} is not a Compose service"],
        }

    _validate_lifecycle(service_id, service)
    source = _compose_source(service_id, service)
    enabled = bool(service.get("enabled"))
    return {
        "service": service_id,
        "runtime": "podman-compose",
        "source": str(source),
        "project": service_id,
        "enabled": enabled,
        "lifecycle": (service.get("lifecycle") or {}).get("mode"),
        "actions": [
            {
                "type": "podman-compose",
                "operation": "up" if enabled else "down",
                "project": service_id,
                "source": str(source),
            }
        ],
    }


def apply_compose(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_compose(service_id, service)
    if dry_run or not plan["actions"]:
        return plan

    command = [
        "podman",
        "compose",
        "-p",
        plan["project"],
        "-f",
        plan["source"],
    ]
    if plan["enabled"]:
        command.extend(["up", "-d"])
    else:
        command.extend(["down", "--remove-orphans"])
    subprocess.run(command, check=True)
    return plan


def remove_compose(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> None:
    if dry_run:
        return
    candidate = dict(service)
    candidate["enabled"] = False
    plan = plan_compose(service_id, candidate)
    if not plan["actions"]:
        return
    subprocess.run(
        [
            "podman",
            "compose",
            "-p",
            plan["project"],
            "-f",
            plan["source"],
            "down",
            "--remove-orphans",
        ],
        check=True,
    )
