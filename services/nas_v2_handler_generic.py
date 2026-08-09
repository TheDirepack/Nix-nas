#!/usr/bin/env python3
"""Default per-service handler for the Managed Services V2 schema runtime.

The handler contains no application names.  It is the normal choice for V2
services; application-specific modules are an escape hatch and use the same
small ABI so custom branches never leak into the shared wrapper.
"""

from __future__ import annotations

import subprocess
from typing import Any


class V2HandlerError(RuntimeError):
    pass


def validate(service_id: str, service: dict[str, Any], document: dict[str, Any]) -> None:
    """Validate handler-specific data.  The generic handler has no extra fields."""

    options = (service.get("handler") or {}).get("options", {})
    if not isinstance(options, dict):
        raise V2HandlerError(f"Service {service_id}: handler.options must be an object")


def prepare(service_id: str, service: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    """Return the service unchanged after optional handler preparation."""

    return service


def _systemd_apply(service_id: str, service: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    runtime = service["runtime"]
    units = runtime.get("units", [])
    if not isinstance(units, list) or not units:
        raise V2HandlerError(f"Service {service_id}: systemd runtime requires units")
    workload = service["workload"]
    kind = workload["kind"]
    managed = bool(service.get("managed", True))
    enabled = bool(service.get("enabled"))

    operation: str | None = None
    if not enabled and managed:
        operation = "stop"
    elif kind == "daemon" and workload.get("activation") == "persistent":
        operation = "start"
    elif kind in {"job", "session"} or workload.get("activation") == "on-demand":
        operation = None

    plan = {"service": service_id, "runtime": "systemd", "operation": operation, "units": units}
    if operation is not None and not dry_run:
        subprocess.run(["systemctl", operation, *units], check=True)
    return plan


def apply_runtime(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    """Apply steady-state runtime intent using generic native adapters."""

    runtime_type = (service.get("runtime") or {}).get("type")
    if runtime_type == "systemd":
        return _systemd_apply(service_id, service, dry_run=dry_run)

    workload = service["workload"]
    kind = workload["kind"]
    if kind in {"job", "session"}:
        return {"service": service_id, "runtime": runtime_type, "operation": None}

    desired = bool(service.get("enabled")) and workload.get("activation") == "persistent"
    projected = dict(service)
    projected["enabled"] = desired
    projected["lifecycle"] = {
        "mode": "persistent" if workload.get("activation") == "persistent" else "on-demand",
        **({"idleSeconds": workload["idleSeconds"]} if workload.get("activation") == "on-demand" else {}),
    }

    if runtime_type == "quadlet":
        from nas_service_runtime_podman import apply_podman

        return apply_podman(service_id, projected, dry_run=dry_run)
    if runtime_type == "compose":
        from nas_service_runtime_compose import apply_compose

        return apply_compose(service_id, projected, dry_run=dry_run)
    if runtime_type == "vm":
        from nas_service_runtime_libvirt import apply_libvirt

        return apply_libvirt(service_id, projected, dry_run=dry_run)
    if runtime_type in {"oci", "exec"}:
        return {
            "service": service_id,
            "runtime": runtime_type,
            "operation": None,
            "note": "OCI session and generic exec materialization are activated by the V2 session/job engine, not steady-state reconcile",
        }
    raise V2HandlerError(f"Service {service_id}: unsupported runtime type {runtime_type!r}")
