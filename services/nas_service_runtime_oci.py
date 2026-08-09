#!/usr/bin/env python3
"""Generic direct Podman OCI runtime for Managed Services V2."""

from __future__ import annotations

import re
import subprocess
from typing import Any

from nas_v2_podman_network import ensure_network

SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
INSTANCE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class OCIRuntimeError(RuntimeError):
    pass


def container_name(service_id: str, instance_id: str | None = None) -> str:
    if SERVICE_ID_RE.fullmatch(service_id) is None:
        raise OCIRuntimeError(f"Invalid V2 service id {service_id!r}")
    if instance_id is None:
        return f"nas-v2-{service_id}"
    if INSTANCE_RE.fullmatch(instance_id) is None:
        raise OCIRuntimeError(f"Invalid V2 OCI instance id {instance_id!r}")
    return f"nas-v2-{service_id}-{instance_id}"


def _runtime(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("type") != "oci":
        raise OCIRuntimeError(f"Service {service_id}: runtime.type must be oci")
    return runtime


def _add_resources(command: list[str], service: dict[str, Any]) -> None:
    resources = service.get("resources") or {}
    if resources.get("memoryMaxBytes") is not None:
        command.extend(["--memory", str(int(resources["memoryMaxBytes"]))])
    if resources.get("memoryHighBytes") is not None:
        command.extend(["--memory-reservation", str(int(resources["memoryHighBytes"]))])
    if resources.get("cpus") is not None:
        command.extend(["--cpus", str(float(resources["cpus"]))])
    if resources.get("pids") is not None:
        command.extend(["--pids-limit", str(int(resources["pids"]))])


def _add_sandbox(command: list[str], service: dict[str, Any]) -> None:
    sandbox = service.get("sandbox") or {}
    profile = sandbox.get("profile", "inherit")
    if profile in {"strict", "standard"}:
        command.extend(["--security-opt", "no-new-privileges", "--cap-drop", "all"])
    if sandbox.get("readOnlyRoot") is True:
        command.append("--read-only")
    for capability in sandbox.get("addLinuxCapabilities") or []:
        name = str(capability).removeprefix("CAP_").lower()
        command.extend(["--cap-add", name])


def _add_mounts(command: list[str], service: dict[str, Any]) -> None:
    for mount in service.get("resolvedStorage") or []:
        if not isinstance(mount, dict) or "hostPath" not in mount:
            continue
        host = mount.get("hostPath")
        guest = mount.get("guestPath")
        mode = mount.get("mode")
        if not isinstance(host, str) or not host.startswith("/") or not isinstance(guest, str) or not guest.startswith("/"):
            raise OCIRuntimeError("OCI resolved storage paths must be absolute")
        if mode not in {"ro", "rw"}:
            raise OCIRuntimeError("OCI resolved storage mode must be ro or rw")
        command.extend(["--volume", f"{host}:{guest}:{mode}"])
    for credential in service.get("credentials") or []:
        if not isinstance(credential, dict):
            continue
        source = credential.get("resolvedPath")
        if not isinstance(source, str) or not source.startswith("/run/nas-secrets/"):
            continue
        if credential.get("use") == "environment-file":
            command.extend(["--env-file", source])
        elif credential.get("use") == "file":
            target = credential.get("mountPath")
            if not isinstance(target, str) or not target.startswith("/"):
                raise OCIRuntimeError("OCI credential file attachment requires absolute mountPath")
            command.extend(["--volume", f"{source}:{target}:ro"])


def _add_devices(command: list[str], service: dict[str, Any]) -> None:
    seen: set[str] = set()
    for request in service.get("resolvedDevices") or []:
        if not isinstance(request, dict):
            continue
        for device in request.get("cdiDevices", []):
            if isinstance(device, str) and device and device not in seen:
                command.extend(["--device", device])
                seen.add(device)
        for device in request.get("devicePaths", []):
            if isinstance(device, str) and device.startswith("/dev/") and device not in seen:
                # NVIDIA CDI already injects the required device set/libraries.
                if any(item.startswith("nvidia.com/") for item in seen) and device.startswith("/dev/nvidia"):
                    continue
                command.extend(["--device", f"{device}:{device}:rwm"])
                seen.add(device)


def _add_network(service_id: str, command: list[str], service: dict[str, Any], *, dry_run: bool) -> dict[str, Any] | None:
    resolved = service.get("resolvedNetwork")
    if resolved is None:
        network = service.get("network") or {}
        mode = network.get("mode", "host")
        if mode == "none":
            command.extend(["--network", "none"])
        elif mode == "host":
            command.extend(["--network", "host"])
        return None
    if not isinstance(resolved, dict):
        raise OCIRuntimeError(f"Service {service_id}: resolvedNetwork must be an object")
    plan = ensure_network(service_id, resolved, dry_run=dry_run)
    command.extend(["--network", plan["networkName"]])
    return plan


def podman_command(
    service_id: str,
    service: dict[str, Any],
    *,
    mode: str,
    instance_id: str | None = None,
    dry_run: bool = False,
) -> tuple[list[str], dict[str, Any] | None]:
    runtime = _runtime(service_id, service)
    if mode not in {"daemon", "job", "session"}:
        raise OCIRuntimeError(f"Invalid OCI execution mode {mode!r}")
    name = container_name(service_id, instance_id if mode == "session" else None)
    command = ["podman", "run", "--name", name]
    if mode == "daemon":
        command.extend(["--detach", "--replace", "--restart", "on-failure"])
    elif mode == "session":
        command.extend(["--detach", "--rm"])
    else:
        command.append("--rm")
    pull = runtime.get("pull", "missing")
    command.extend(["--pull", pull])
    user = runtime.get("user")
    if user:
        command.extend(["--user", str(user)])
    for key, value in sorted((runtime.get("environment") or {}).items()):
        if not isinstance(value, str) or any(char in value for char in ("\x00", "\r", "\n")):
            raise OCIRuntimeError(f"Service {service_id}: invalid OCI environment value for {key!r}")
        command.extend(["--env", f"{key}={value}"])
    _add_resources(command, service)
    _add_sandbox(command, service)
    _add_mounts(command, service)
    _add_devices(command, service)
    network = _add_network(service_id, command, service, dry_run=dry_run)
    command.append(runtime["image"])
    command.extend(runtime.get("command") or [])
    return command, network


def start_oci(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    command, network = podman_command(service_id, service, mode="daemon", dry_run=dry_run)
    plan = {"service": service_id, "runtime": "oci", "operation": "start", "command": command, "network": network}
    if not dry_run:
        subprocess.run(command, check=True)
    return plan


def stop_oci(service_id: str, *, dry_run: bool = False) -> dict[str, Any]:
    name = container_name(service_id)
    if not dry_run:
        subprocess.run(["podman", "stop", name], check=False)
        subprocess.run(["podman", "rm", "-f", name], check=False)
    return {"service": service_id, "runtime": "oci", "operation": "stop", "container": name}


def run_oci_job(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    command, network = podman_command(service_id, service, mode="job", dry_run=dry_run)
    if dry_run:
        return {"service": service_id, "runtime": "oci", "operation": "run-job", "command": command, "network": network}
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise OCIRuntimeError(f"Service {service_id}: OCI job failed with exit code {result.returncode}")
    return {"service": service_id, "runtime": "oci", "operation": "run-job", "exitCode": result.returncode}


def begin_oci_session(
    service_id: str,
    session_id: str,
    service: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    command, network = podman_command(
        service_id,
        service,
        mode="session",
        instance_id=session_id,
        dry_run=dry_run,
    )
    plan = {
        "service": service_id,
        "runtime": "oci",
        "operation": "session-begin",
        "container": container_name(service_id, session_id),
        "command": command,
        "network": network,
    }
    if not dry_run:
        subprocess.run(command, check=True)
    return plan


def end_oci_session(service_id: str, session_id: str, *, dry_run: bool = False) -> dict[str, Any]:
    name = container_name(service_id, session_id)
    if not dry_run:
        subprocess.run(["podman", "stop", name], check=False)
    return {"service": service_id, "runtime": "oci", "operation": "session-end", "container": name}
