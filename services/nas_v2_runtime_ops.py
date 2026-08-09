#!/usr/bin/env python3
"""Single generic runtime-operation boundary for Managed Services V2."""

from __future__ import annotations

import subprocess
from typing import Any


class V2RuntimeOperationError(RuntimeError):
    pass


def _systemd_unit(service_id: str, service: dict[str, Any]) -> str:
    runtime_type = service["runtime"]["type"]
    if runtime_type == "systemd":
        return service["runtime"]["unit"]
    if runtime_type == "python":
        from nas_service_runtime_python import unit_name

        return unit_name(service_id)
    if runtime_type == "exec":
        from nas_service_runtime_exec import unit_name

        return unit_name(service_id)
    raise V2RuntimeOperationError(f"Service {service_id}: runtime {runtime_type!r} has no systemd unit")


def _materialize_systemd_backed(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    runtime_type = service["runtime"]["type"]
    if runtime_type == "python":
        from nas_service_runtime_python import apply_python

        return apply_python(service_id, service, dry_run=dry_run)
    if runtime_type == "exec":
        from nas_service_runtime_exec import materialize_exec

        return materialize_exec(service_id, service, dry_run=dry_run)
    return {"service": service_id, "runtime": runtime_type, "unit": _systemd_unit(service_id, service)}


def reconcile(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    runtime_type = service["runtime"]["type"]
    workload = service["workload"]
    enabled = bool(service.get("enabled"))
    managed = bool(service.get("managed", True))
    persistent = workload["kind"] == "daemon" and workload.get("activation") == "persistent"

    if runtime_type in {"systemd", "python", "exec"}:
        materialized = _materialize_systemd_backed(service_id, service, dry_run=dry_run)
        unit = _systemd_unit(service_id, service)
        operation = "stop" if managed and not enabled else ("start" if enabled and persistent else None)
        if operation is not None and not dry_run:
            subprocess.run(["systemctl", operation, unit], check=True)
        return {**materialized, "operation": operation}

    if workload["kind"] in {"job", "session"}:
        return {"service": service_id, "runtime": runtime_type, "operation": None}

    projected = dict(service)
    projected["enabled"] = bool(enabled and persistent)
    if runtime_type == "quadlet":
        from nas_service_runtime_podman import apply_podman

        return apply_podman(service_id, projected, dry_run=dry_run)
    if runtime_type == "compose":
        from nas_service_runtime_compose import apply_compose

        return apply_compose(service_id, projected, dry_run=dry_run)
    if runtime_type == "vm":
        from nas_service_runtime_libvirt import apply_libvirt

        return apply_libvirt(service_id, projected, dry_run=dry_run)
    if runtime_type == "oci":
        from nas_service_runtime_oci import start_oci, stop_oci

        if not enabled and managed:
            return stop_oci(service_id, dry_run=dry_run)
        if persistent:
            return start_oci(service_id, service, dry_run=dry_run)
        return {"service": service_id, "runtime": "oci", "operation": None}
    raise V2RuntimeOperationError(f"Service {service_id}: unsupported runtime {runtime_type!r}")


def start(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    runtime_type = service["runtime"]["type"]
    if runtime_type in {"systemd", "python", "exec"}:
        materialized = _materialize_systemd_backed(service_id, service, dry_run=dry_run)
        unit = _systemd_unit(service_id, service)
        if not dry_run:
            subprocess.run(["systemctl", "start", unit], check=True)
        return {**materialized, "operation": "start", "unit": unit}
    projected = dict(service)
    projected["enabled"] = True
    if runtime_type == "quadlet":
        from nas_service_runtime_podman import apply_podman

        return apply_podman(service_id, projected, dry_run=dry_run)
    if runtime_type == "compose":
        from nas_service_runtime_compose import apply_compose

        return apply_compose(service_id, projected, dry_run=dry_run)
    if runtime_type == "vm":
        from nas_service_runtime_libvirt import apply_libvirt

        return apply_libvirt(service_id, projected, dry_run=dry_run)
    if runtime_type == "oci":
        from nas_service_runtime_oci import start_oci

        return start_oci(service_id, service, dry_run=dry_run)
    raise V2RuntimeOperationError(f"Service {service_id}: unsupported runtime {runtime_type!r}")


def stop(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    runtime_type = service["runtime"]["type"]
    if runtime_type in {"systemd", "python", "exec"}:
        unit = _systemd_unit(service_id, service)
        if not dry_run:
            subprocess.run(["systemctl", "stop", unit], check=False)
        return {"service": service_id, "runtime": runtime_type, "operation": "stop", "unit": unit}
    projected = dict(service)
    projected["enabled"] = False
    if runtime_type == "quadlet":
        from nas_service_runtime_podman import apply_podman

        return apply_podman(service_id, projected, dry_run=dry_run)
    if runtime_type == "compose":
        from nas_service_runtime_compose import apply_compose

        return apply_compose(service_id, projected, dry_run=dry_run)
    if runtime_type == "vm":
        from nas_service_runtime_libvirt import apply_libvirt

        return apply_libvirt(service_id, projected, dry_run=dry_run)
    if runtime_type == "oci":
        from nas_service_runtime_oci import stop_oci

        return stop_oci(service_id, dry_run=dry_run)
    raise V2RuntimeOperationError(f"Service {service_id}: unsupported runtime {runtime_type!r}")


def run_job(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    runtime_type = service["runtime"]["type"]
    if runtime_type in {"systemd", "python", "exec"}:
        materialized = _materialize_systemd_backed(service_id, service, dry_run=dry_run)
        unit = _systemd_unit(service_id, service)
        if dry_run:
            return {**materialized, "operation": "run-job", "unit": unit}
        result = subprocess.run(["systemctl", "start", "--wait", unit], check=False)
        if result.returncode != 0:
            raise V2RuntimeOperationError(f"Service {service_id}: job unit {unit} failed")
        return {**materialized, "operation": "run-job", "unit": unit, "exitCode": result.returncode}
    if runtime_type == "oci":
        from nas_service_runtime_oci import run_oci_job

        return run_oci_job(service_id, service, dry_run=dry_run)
    raise V2RuntimeOperationError(f"Service {service_id}: runtime {runtime_type!r} does not support generic jobs")


def begin_session(
    service_id: str,
    session_id: str,
    service: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    runtime_type = service["runtime"]["type"]
    if runtime_type == "oci":
        from nas_service_runtime_oci import begin_oci_session

        return begin_oci_session(service_id, session_id, service, dry_run=dry_run)
    if runtime_type in {"systemd", "python", "exec"}:
        return start(service_id, service, dry_run=dry_run)
    raise V2RuntimeOperationError(
        f"Service {service_id}: runtime {runtime_type!r} does not implement disposable session semantics"
    )


def end_session(
    service_id: str,
    session_id: str,
    service: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    runtime_type = service["runtime"]["type"]
    if runtime_type == "oci":
        from nas_service_runtime_oci import end_oci_session

        return end_oci_session(service_id, session_id, dry_run=dry_run)
    if runtime_type in {"systemd", "python", "exec"}:
        return stop(service_id, service, dry_run=dry_run)
    raise V2RuntimeOperationError(
        f"Service {service_id}: runtime {runtime_type!r} does not implement disposable session semantics"
    )
