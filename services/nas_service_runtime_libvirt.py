#!/usr/bin/env python3
"""Thin libvirt/QEMU/KVM runtime adapter for managed services.

Managed Services V2 owns NAS policy. libvirt owns the domain definition. The
adapter therefore validates and applies the native XML source rather than
re-rendering a partial domain, and removing an application never implicitly
deletes its disks or other persistent storage.
"""

from __future__ import annotations

import pathlib
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError

APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")


def _domain_source(service_id: str, service: dict[str, Any]) -> pathlib.Path:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "vm":
        raise ManagedServiceError(f"Service {service_id} is not a VM service")
    source = runtime.get("source", "")
    if not isinstance(source, str) or not pathlib.PurePosixPath(source).is_absolute():
        raise ManagedServiceError(f"VM source for {service_id} must be under {APP_ROOT / service_id}/")
    app_root = APP_ROOT.resolve()
    root = (app_root / service_id).resolve()
    path = pathlib.Path(source).resolve()
    try:
        root.relative_to(app_root)
        path.relative_to(root)
    except ValueError as exc:
        raise ManagedServiceError(f"VM source for {service_id} must be under {root}/") from exc
    if path.suffix != ".xml":
        raise ManagedServiceError(f"VM source for {service_id} must be a native libvirt .xml definition")
    return path


def _validate_lifecycle(service_id: str, service: dict[str, Any]) -> None:
    lifecycle = service.get("lifecycle") or {}
    if lifecycle.get("mode") == "session" and service.get("enabled"):
        raise ManagedServiceError(
            f"Service {service_id}: session lifecycle is not supported for libvirt domains; "
            "use an explicit disposable clone/overlay workflow"
        )


def plan_libvirt(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "vm":
        return {"actions": [], "warnings": [f"Service {service_id} is not a VM service"]}
    _validate_lifecycle(service_id, service)
    source = _domain_source(service_id, service)
    enabled = bool(service.get("enabled"))
    return {
        "service": service_id,
        "runtime": "libvirt",
        "source": str(source),
        "domain": service_id,
        "enabled": enabled,
        "lifecycle": (service.get("lifecycle") or {}).get("mode"),
        "resolvedStorage": service.get("resolvedStorage", []),
        "actions": [
            {"type": "virsh-define", "domain": service_id, "source": str(source)},
            {"type": "virsh-domain", "domain": service_id, "operation": "start" if enabled else "destroy"},
        ],
    }


def apply_libvirt(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_libvirt(service_id, service)
    if dry_run or not plan["actions"]:
        return plan
    subprocess.run(["virsh", "define", plan["source"]], check=True)
    if plan["enabled"]:
        # Starting an already-running domain is harmlessly avoided using domstate
        # rather than treating lifecycle state as another NAS-owned database.
        state = subprocess.run(
            ["virsh", "domstate", service_id],
            check=False,
            capture_output=True,
            text=True,
        )
        if state.returncode != 0 or state.stdout.strip().lower() not in {"running", "blocked", "paused"}:
            subprocess.run(["virsh", "start", service_id], check=True)
    else:
        subprocess.run(["virsh", "destroy", service_id], check=False)
    return plan


def remove_libvirt(service_id: str, *, dry_run: bool = False) -> None:
    """Remove only the runtime domain definition; persistent storage is explicit."""

    if dry_run:
        return
    subprocess.run(["virsh", "destroy", service_id], check=False)
    # --nvram removes firmware runtime state only. Deliberately do not use
    # --remove-all-storage: authoritative disks/datasets require an explicit
    # storage-resource deletion operation.
    result = subprocess.run(["virsh", "undefine", service_id, "--nvram"], check=False)
    if result.returncode != 0:
        subprocess.run(["virsh", "undefine", service_id], check=True)
