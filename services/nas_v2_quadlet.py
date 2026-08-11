#!/usr/bin/env python3
"""Render Managed Services V2 Quadlet/OCI runtime projections.

This module translates container-specific policy. systemd remains the lifecycle
owner, while resource limits that must constrain the container payload are also
lowered into Podman-native options instead of relying only on the wrapper unit.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

from nas_v2_accelerator import is_cdi_selector
from nas_v2_podman_network import (
    PodmanNetworkProjectionError,
    network_policy,
    quadlet_network_reference,
)


class QuadletProjectionError(RuntimeError):
    """Raised when a container runtime cannot be represented faithfully."""


_INSTALL_SECTION_RE = re.compile(r"(?mi)^\s*\[Install\]\s*$")
_SERVICE_NAME_RE = re.compile(r"(?mi)^\s*ServiceName\s*=")
_NETWORK_RE = re.compile(r"(?mi)^\s*Network\s*=")
_PUBLISH_PORT_RE = re.compile(r"(?mi)^\s*PublishPort\s*=")
_PODMAN_ARGS_RE = re.compile(r"(?mi)^\s*PodmanArgs\s*=")
_STRICT_SOURCE_KEY_RE = re.compile(
    r"(?mi)^\s*(?:ReadOnly|NoNewPrivileges|AddCapability|DropCapability|Tmpfs|AddDevice)\s*="
)
_DEV_ROOT = pathlib.PurePosixPath("/dev")
_LOOPBACK_HOSTS = {"127.0.0.1": "127.0.0.1", "localhost": "127.0.0.1", "::1": "[::1]"}


def _single_line(value: str, *, field: str) -> str:
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise QuadletProjectionError(f"{field} contains a forbidden control character")
    return value.replace("%", "%%")


def _quote(value: str, *, field: str = "Quadlet value") -> str:
    safe = _single_line(value, field=field)
    return '"' + safe.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _safe_path(value: str, *, field: str, allow_colon: bool = False) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise QuadletProjectionError(f"{field} must be an absolute safe path")
    if not allow_colon and ":" in value:
        raise QuadletProjectionError(f"{field} may not contain ':'")
    return path


def _network_lines(effective: dict[str, Any], service_id: str, service: dict[str, Any]) -> list[str]:
    try:
        reference = quadlet_network_reference(effective, service_id, service)
    except PodmanNetworkProjectionError as exc:
        raise QuadletProjectionError(str(exc)) from exc
    return [f"Network={reference}"]


def _listener_ports(service: dict[str, Any]) -> set[tuple[str, int]]:
    ports: set[tuple[str, int]] = set()
    listeners = service.get("listeners", {})
    if not isinstance(listeners, dict):
        return ports
    for listener in listeners.values():
        if not isinstance(listener, dict):
            continue
        protocol = listener.get("protocol")
        exposure = listener.get("exposure")
        if protocol not in {"tcp", "udp"} or not isinstance(exposure, dict):
            continue
        if isinstance(exposure.get("port"), int):
            ports.add((protocol, exposure["port"]))
        elif isinstance(exposure.get("start"), int) and isinstance(exposure.get("end"), int):
            ports.update((protocol, port) for port in range(exposure["start"], exposure["end"] + 1))
    return ports


def _publish_lines(effective: dict[str, Any], service_id: str, service: dict[str, Any]) -> list[str]:
    policy = network_policy(effective, service)
    if policy.get("mode", "host") != "isolated":
        return []

    lines: list[str] = []
    published = _listener_ports(service)
    listeners = service.get("listeners", {})
    if isinstance(listeners, dict):
        for listener_id in sorted(listeners):
            listener = listeners[listener_id]
            if not isinstance(listener, dict):
                continue
            protocol = listener["protocol"]
            exposure = listener["exposure"]
            if "port" in exposure:
                value = f"{exposure['port']}:{exposure['port']}/{protocol}"
            else:
                value = f"{exposure['start']}-{exposure['end']}:{exposure['start']}-{exposure['end']}/{protocol}"
            lines.append(f"PublishPort={_quote(value, field=f'listener {listener_id!r} publication')}")

    routes = service.get("routes", {})
    if isinstance(routes, dict):
        for route_id in sorted(routes):
            route = routes[route_id]
            if not isinstance(route, dict):
                continue
            target = route.get("target")
            if not isinstance(target, dict):
                continue
            if target.get("type") == "unix-http":
                raise QuadletProjectionError(
                    f"isolated container route {route_id!r} cannot target a host Unix socket; use a TCP route target"
                )
            host = target.get("host", "127.0.0.1")
            bind_host = _LOOPBACK_HOSTS.get(host) if isinstance(host, str) else None
            if bind_host is None:
                raise QuadletProjectionError(
                    f"isolated container route {route_id!r} must use a loopback host target so Caddy cannot expose an unintended bind"
                )
            port = target.get("port")
            if not isinstance(port, int):
                raise QuadletProjectionError(f"isolated container route {route_id!r} is missing its TCP target port")
            if ("tcp", port) in published:
                continue
            lines.append(
                f"PublishPort={_quote(f'{bind_host}:{port}:{port}/tcp', field=f'route {route_id!r} publication')}"
            )
            published.add(("tcp", port))
    return lines


def _storage_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    resources = effective.get("storageResources", {})
    if not isinstance(resources, dict):
        raise QuadletProjectionError("compiled storageResources must be an object")
    lines: list[str] = []
    for attachment in service.get("storage", []):
        resource_id = attachment.get("resource") if isinstance(attachment, dict) else None
        resource = resources.get(resource_id) if isinstance(resource_id, str) else None
        if not isinstance(resource, dict) or not isinstance(resource.get("path"), str):
            raise QuadletProjectionError(f"storage resource {resource_id!r} is missing")
        source = _safe_path(resource["path"], field=f"storage resource {resource_id!r} path")
        mount = attachment.get("mountPath")
        if not isinstance(mount, str):
            raise QuadletProjectionError("storage attachment mountPath is missing")
        destination = _safe_path(mount, field="storage attachment mountPath")
        access = attachment.get("access", "read")
        if access not in {"read", "write"}:
            raise QuadletProjectionError(f"unsupported storage access mode {access!r}")
        option = "ro" if access == "read" else "rw"
        lines.append(f"Volume={_quote(f'{source}:{destination}:{option}', field='storage volume')}")
    return lines


def _credential_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    credentials = effective.get("credentials", {})
    if not isinstance(credentials, dict):
        raise QuadletProjectionError("compiled credentials must be an object")
    lines: list[str] = []
    for attachment in service.get("credentials", []):
        credential_id = attachment.get("credential") if isinstance(attachment, dict) else None
        credential = credentials.get(credential_id) if isinstance(credential_id, str) else None
        if not isinstance(credential, dict) or not isinstance(credential.get("path"), str):
            raise QuadletProjectionError(f"credential {credential_id!r} is missing")
        source = _safe_path(credential["path"], field=f"credential {credential_id!r} path")
        required = credential.get("required") is not False
        use = attachment.get("use")
        if use == "environment-file":
            if not required:
                raise QuadletProjectionError(
                    f"optional OCI environment credential {credential_id!r} is not representable yet"
                )
            lines.append(f"EnvironmentFile={_quote(str(source), field='credential path')}")
            continue
        if use == "file":
            if not required:
                raise QuadletProjectionError(f"optional OCI file credential {credential_id!r} is not representable yet")
            mount = attachment.get("mountPath")
            if not isinstance(mount, str):
                raise QuadletProjectionError(f"file credential {credential_id!r} is missing mountPath")
            destination = _safe_path(mount, field=f"credential {credential_id!r} mountPath")
            lines.append(f"Volume={_quote(f'{source}:{destination}:ro', field='credential volume')}")
            continue
        if use == "native-reference":
            raise QuadletProjectionError(
                f"OCI native-reference credential {credential_id!r} requires Podman secret reconciliation"
            )
        raise QuadletProjectionError(f"unsupported credential use {use!r}")
    return lines


def _resource_lines(service: dict[str, Any]) -> list[str]:
    """Lower scalar limits into the actual container cgroup as well as systemd."""
    resources = service.get("resources", {})
    if not isinstance(resources, dict):
        return []
    lines: list[str] = []
    cpu = resources.get("cpuQuotaPercent")
    memory_high = resources.get("memoryHighBytes")
    memory_max = resources.get("memoryMaxBytes")
    pids = resources.get("pidsMax")
    if cpu is not None:
        cpus = format(cpu / 100, ".12g")
        lines.append(f"PodmanArgs=--cpus={cpus}")
    if memory_high is not None:
        lines.append(f"PodmanArgs=--memory-reservation={memory_high}b")
    if memory_max is not None:
        lines.append(f"Memory={memory_max}b")
    if pids is not None:
        lines.append(f"PidsLimit={pids}")
    return lines


def _sandbox_lines(service: dict[str, Any]) -> list[str]:
    sandbox = service.get("sandbox", {})
    if not isinstance(sandbox, dict) or sandbox.get("mode") == "inherit":
        return []
    writable_paths = sandbox.get("writablePaths", [])
    if writable_paths:
        raise QuadletProjectionError(
            "OCI sandbox.writablePaths requires explicit storage/tmpfs projection rather than implicit host access"
        )
    lines: list[str] = []
    if sandbox.get("readOnlyRoot", True):
        lines.append("ReadOnly=true")
    if sandbox.get("noNewPrivileges", True):
        lines.append("NoNewPrivileges=true")
    add = sandbox.get("addCapabilities", [])
    drop = sandbox.get("dropCapabilities", [])
    if add:
        lines.append("AddCapability=" + " ".join(_single_line(item, field="capability") for item in add))
    if drop:
        lines.append("DropCapability=" + " ".join(_single_line(item, field="capability") for item in drop))
    for entry in sandbox.get("tmpfs", []):
        path = _safe_path(entry["path"], field="tmpfs path")
        value = str(path)
        if "sizeBytes" in entry:
            value += f":size={entry['sizeBytes']}"
        lines.append(f"Tmpfs={_quote(value, field='tmpfs')}")
    return lines


def _accelerator_lines(service: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for accelerator in service.get("resources", {}).get("accelerators", []):
        if accelerator.get("mode", "shared") != "shared":
            raise QuadletProjectionError("OCI accelerators support shared mode only")
        if accelerator.get("quantity", 1) != 1:
            raise QuadletProjectionError("resolved OCI accelerator selectors must use quantity=1")
        device = accelerator.get("device")
        if not isinstance(device, str):
            raise QuadletProjectionError("OCI accelerator request was not resolved to a concrete selector")
        if is_cdi_selector(device):
            if accelerator.get("target") is not None:
                raise QuadletProjectionError("CDI accelerator selectors may not declare a device-path target")
            lines.append(f"PodmanArgs=--device={_quote(device, field='CDI accelerator selector')}")
            continue
        device_path = _safe_path(device, field="accelerator device")
        try:
            device_path.relative_to(_DEV_ROOT)
        except ValueError as exc:
            raise QuadletProjectionError("OCI accelerator device must be beneath /dev") from exc
        target = accelerator.get("target")
        value = str(device_path)
        if target is not None:
            if not isinstance(target, str):
                raise QuadletProjectionError("OCI accelerator target must be a path")
            target_path = _safe_path(target, field="accelerator target")
            try:
                target_path.relative_to(_DEV_ROOT)
            except ValueError as exc:
                raise QuadletProjectionError("OCI accelerator target must be beneath /dev") from exc
            value += f":{target_path}"
        value += ":rw"
        lines.append(f"AddDevice={_quote(value, field='accelerator device mapping')}")
    return lines


def _container_policy_lines(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
) -> list[str]:
    return [
        *_network_lines(effective, service_id, service),
        *_publish_lines(effective, service_id, service),
        *_storage_lines(effective, service),
        *_credential_lines(effective, service),
        *_resource_lines(service),
        *_sandbox_lines(service),
        *_accelerator_lines(service),
    ]


def _sections(unit_lines: list[str], container_lines: list[str], service_lines: list[str]) -> str:
    rendered: list[str] = []
    if unit_lines:
        rendered.extend(["[Unit]", *unit_lines, ""])
    if container_lines:
        rendered.extend(["[Container]", *container_lines, ""])
    if service_lines:
        rendered.extend(["[Service]", *service_lines, ""])
    return "\n".join(rendered)


def render_quadlet(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    unit_lines: list[str],
    service_lines: list[str],
) -> bytes:
    """Render one `.container` source for an OCI or raw-Quadlet runtime."""
    runtime = service["runtime"]
    runtime_type = runtime["type"]
    policy = _container_policy_lines(effective, service_id, service)

    if runtime_type == "oci":
        container_lines = [
            f"Image={_quote(runtime['image'], field='OCI image')}",
            f"Pull={runtime['pull']}",
        ]
        if runtime["command"]:
            container_lines.append(
                "Exec=" + " ".join(_quote(argument, field="OCI command argument") for argument in runtime["command"])
            )
        container_lines.extend(policy)
        return _sections(unit_lines, container_lines, service_lines).encode("utf-8")

    if runtime_type != "quadlet":
        raise QuadletProjectionError(f"runtime {runtime_type!r} is not a Quadlet runtime")

    source = pathlib.Path(runtime["source"])
    if source.suffix != ".container":
        raise QuadletProjectionError("V2 quadlet runtime currently supports .container sources only")
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise QuadletProjectionError(f"unable to read Quadlet source {source}: {exc}") from exc
    if _INSTALL_SECTION_RE.search(text):
        raise QuadletProjectionError("managed Quadlet sources may not contain an [Install] section")
    if _SERVICE_NAME_RE.search(text):
        raise QuadletProjectionError("managed Quadlet sources may not override ServiceName")
    if _NETWORK_RE.search(text):
        raise QuadletProjectionError("managed Quadlet sources may not declare Network; V2 owns network policy")
    if _PUBLISH_PORT_RE.search(text):
        raise QuadletProjectionError("managed Quadlet sources may not declare PublishPort; V2 owns listener exposure")
    if _PODMAN_ARGS_RE.search(text):
        raise QuadletProjectionError(
            "managed Quadlet sources may not declare PodmanArgs; V2 owns generated Podman flags"
        )
    if service.get("sandbox", {}).get("mode") == "strict" and _STRICT_SOURCE_KEY_RE.search(text):
        raise QuadletProjectionError(
            "managed Quadlet source declares container security fields that conflict with V2 strict sandboxing"
        )
    if not text.endswith("\n"):
        text += "\n"
    overlay = _sections(unit_lines, policy, service_lines)
    if overlay:
        text += "\n" + overlay
    return text.encode("utf-8")


def validate_quadlets(files: dict[pathlib.Path, bytes], *, generator_bin: str) -> None:
    """Run Podman's native Quadlet generator in dry-run mode before activation."""
    quadlets = {
        path: data
        for path, data in files.items()
        if path.suffix in {".container", ".volume", ".network", ".pod", ".kube", ".image", ".build"}
    }
    if not quadlets:
        return
    with tempfile.TemporaryDirectory(prefix="nas-v2-quadlet-verify-") as raw_tmp:
        root = pathlib.Path(raw_tmp)
        for source, data in quadlets.items():
            (root / source.name).write_bytes(data)
        env = os.environ.copy()
        env["QUADLET_UNIT_DIRS"] = str(root)
        try:
            result = subprocess.run(
                [generator_bin, "--dryrun"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise QuadletProjectionError(f"unable to validate Quadlet projection: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise QuadletProjectionError(f"Podman Quadlet generator rejected projection: {detail}")


__all__ = ["QuadletProjectionError", "render_quadlet", "validate_quadlets"]
