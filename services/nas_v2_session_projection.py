#!/usr/bin/env python3
"""Project finite transient Managed Services V2 session workloads.

Session definitions contribute only a shared lifecycle target, a compiler-owned
descriptor, and (when needed) a native Podman network. Individual sessions are
created with ``systemd-run`` by the finite launcher, so no resident session
controller, template database, or user database exists.
"""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
from typing import Any

from nas_v2_accelerator import is_cdi_selector
from nas_v2_network import (
    PodmanNetworkProjectionError,
    podman_network_name,
    quadlet_network_reference,
)
from nas_v2_systemd import generate_projection as generate_base_projection


class SessionProjectionError(RuntimeError):
    """Raised when a session definition cannot be represented safely."""


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _absolute_binary(value: str, *, field: str) -> str:
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SessionProjectionError(f"{field} must be an absolute safe path")
    return value


def _safe_volume_path(value: str, *, field: str) -> str:
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or ":" in value:
        raise SessionProjectionError(f"{field} must be an absolute path without '..' or ':'")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise SessionProjectionError(f"{field} contains a forbidden control character")
    return value


def _template_beneath_root(root: str, template: str, *, placeholder: str) -> None:
    root_path = pathlib.PurePosixPath(_safe_volume_path(root, field="session storage root"))
    token = "{" + placeholder + "}"
    if token not in template:
        raise SessionProjectionError(f"{placeholder}-scoped session storage requires pathTemplate containing {token}")
    probe_value = template.replace(token, f"{placeholder}-probe")
    if "{" in probe_value or "}" in probe_value:
        raise SessionProjectionError(
            f"{placeholder}-scoped session storage pathTemplate contains an unsupported placeholder"
        )
    probe = pathlib.PurePosixPath(_safe_volume_path(probe_value, field="session storage pathTemplate"))
    try:
        probe.relative_to(root_path)
    except ValueError as exc:
        raise SessionProjectionError("session storage pathTemplate must remain beneath the resource path") from exc


def _owner_unit(effective: dict[str, Any], service_id: str) -> str:
    value = effective["derived"]["runtime"][service_id]["ownerUnit"]
    if not isinstance(value, str) or not value.endswith((".service", ".target")):
        raise SessionProjectionError(f"invalid dependency owner for {service_id!r}")
    return value


def _dependency_units(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
) -> tuple[list[str], list[str]]:
    requires: set[str] = set()
    after: set[str] = set()
    for dependency in service["dependencies"]:
        target_id = dependency["service"]
        target_service = effective["services"][target_id]
        if target_service["workload"]["kind"] == "session":
            raise SessionProjectionError(
                f"session service {service_id!r} may not depend on another session template {target_id!r}"
            )
        owner = _owner_unit(effective, target_id)
        requires.add(owner)
        if dependency["condition"] == "ready":
            ready = f"nas-v2-ready-{target_id}.service"
            requires.add(ready)
            after.add(ready)
        else:
            after.add(owner)
    return sorted(requires), sorted(after)


def _session_target(service_id: str) -> str:
    return f"nas-v2-session-{service_id}.target"


def _network_args(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
) -> tuple[list[str], str | None]:
    try:
        reference = quadlet_network_reference(effective, service_id, service)
    except PodmanNetworkProjectionError as exc:
        raise SessionProjectionError(str(exc)) from exc
    if reference == "host":
        return ["--network=host"], None
    if reference == "none":
        return ["--network=none"], None
    network_service = reference.removesuffix(".network") + "-network.service"
    return [f"--network={podman_network_name(service_id, service)}"], network_service


def _storage_projection(
    effective: dict[str, Any],
    service: dict[str, Any],
) -> tuple[list[str], list[dict[str, str]], bool]:
    resources = effective.get("storageResources", {})
    args: list[str] = []
    templates: list[dict[str, str]] = []
    requires_user = False
    for attachment in service["storage"]:
        resource = resources.get(attachment["resource"]) if isinstance(resources, dict) else None
        if not isinstance(resource, dict) or not isinstance(resource.get("path"), str):
            raise SessionProjectionError(f"session storage resource {attachment['resource']!r} is missing")
        root = _safe_volume_path(resource["path"], field="session storage source")
        destination = _safe_volume_path(attachment["mountPath"], field="session storage destination")
        access = "ro" if attachment["access"] == "read" else "rw"
        scope = resource.get("scope", "system")
        if scope == "system":
            args.extend(["--volume", f"{root}:{destination}:{access}"])
            continue
        if scope not in {"instance", "user"}:
            raise SessionProjectionError(f"unsupported session storage scope {scope!r}")
        template = resource.get("pathTemplate")
        if not isinstance(template, str):
            raise SessionProjectionError(f"{scope}-scoped session storage requires pathTemplate")
        _template_beneath_root(root, template, placeholder=scope)
        templates.append(
            {
                "root": root,
                "sourceTemplate": template,
                "target": destination,
                "access": access,
                "scope": scope,
            }
        )
        requires_user = requires_user or scope == "user"
    return args, templates, requires_user


def _credential_args(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    credentials = effective.get("credentials", {})
    args: list[str] = []
    for attachment in service["credentials"]:
        credential = credentials.get(attachment["credential"]) if isinstance(credentials, dict) else None
        if not isinstance(credential, dict) or not isinstance(credential.get("path"), str):
            raise SessionProjectionError(f"session credential {attachment['credential']!r} is missing")
        if credential.get("required", True) is not True:
            raise SessionProjectionError("optional direct-OCI session credentials are not representable yet")
        source = _safe_volume_path(credential["path"], field="session credential path")
        if attachment["use"] == "environment-file":
            args.extend(["--env-file", source])
        elif attachment["use"] == "file":
            mount = attachment.get("mountPath")
            if not isinstance(mount, str):
                raise SessionProjectionError("session file credential requires mountPath")
            destination = _safe_volume_path(mount, field="session credential mount path")
            args.extend(["--volume", f"{source}:{destination}:ro"])
        else:
            raise SessionProjectionError(
                "direct-OCI session native-reference credentials require Podman secret reconciliation"
            )
    return args


def _resource_args(service: dict[str, Any]) -> list[str]:
    resources = service["resources"]
    args: list[str] = []
    if "cpuQuotaPercent" in resources:
        args.extend(["--cpus", format(resources["cpuQuotaPercent"] / 100, ".12g")])
    if "memoryHighBytes" in resources:
        args.extend(["--memory-reservation", f"{resources['memoryHighBytes']}b"])
    if "memoryMaxBytes" in resources:
        args.extend(["--memory", f"{resources['memoryMaxBytes']}b"])
    if "pidsMax" in resources:
        args.extend(["--pids-limit", str(resources["pidsMax"])])
    for accelerator in resources["accelerators"]:
        if accelerator["mode"] != "shared" or accelerator.get("quantity", 1) != 1:
            raise SessionProjectionError("resolved direct-OCI session accelerators must be one shared device selector")
        device = accelerator.get("device")
        if not isinstance(device, str):
            raise SessionProjectionError("direct-OCI session accelerator was not resolved to a concrete selector")
        target = accelerator.get("target")
        if is_cdi_selector(device):
            if target is not None:
                raise SessionProjectionError("CDI accelerator selectors may not declare a device-path target")
            args.extend(["--device", device])
            continue
        if not device.startswith("/dev/"):
            raise SessionProjectionError("direct-OCI session accelerator was not resolved to a host device node")
        source = _safe_volume_path(device, field="session accelerator device")
        if target is not None:
            if not isinstance(target, str):
                raise SessionProjectionError("session accelerator target must be a device path")
            destination = _safe_volume_path(target, field="session accelerator target")
            mapping = f"{source}:{destination}:rw"
        else:
            mapping = f"{source}:{source}:rw"
        args.extend(["--device", mapping])
    return args


def _sandbox_args(service: dict[str, Any]) -> list[str]:
    sandbox = service["sandbox"]
    if sandbox["mode"] == "inherit":
        return []
    if sandbox["writablePaths"]:
        raise SessionProjectionError(
            "direct-OCI session sandbox.writablePaths requires explicit storage/tmpfs projection"
        )
    args: list[str] = []
    if sandbox["readOnlyRoot"]:
        args.append("--read-only")
    if sandbox["noNewPrivileges"]:
        args.extend(["--security-opt", "no-new-privileges"])
    for capability in sandbox["addCapabilities"]:
        args.extend(["--cap-add", capability])
    for capability in sandbox["dropCapabilities"]:
        args.extend(["--cap-drop", capability])
    for mount in sandbox["tmpfs"]:
        path = _safe_volume_path(mount["path"], field="session tmpfs path")
        value = path
        if "sizeBytes" in mount:
            value += f":size={mount['sizeBytes']}"
        args.extend(["--tmpfs", value])
    return args


def _descriptor(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    python_bin: str,
    source_dir: pathlib.Path,
    systemctl_bin: str,
    podman_bin: str,
) -> dict[str, Any]:
    runtime = service["runtime"]
    if runtime["type"] != "oci":
        raise SessionProjectionError(
            f"session service {service_id!r} currently requires direct OCI runtime; {runtime['type']!r} has no transient adapter"
        )
    if service.get("routes") or service.get("listeners"):
        raise SessionProjectionError(
            f"session service {service_id!r} cannot expose fixed routes/listeners because instances need per-instance endpoints"
        )
    if "readiness" in service:
        raise SessionProjectionError(
            f"session service {service_id!r} cannot use a service-global readiness probe; readiness belongs to the authenticated instance launch path"
        )
    if service["workload"].get("schedules"):
        raise SessionProjectionError(f"session service {service_id!r} may not declare schedules")

    _absolute_binary(podman_bin, field="session Podman binary")
    _absolute_binary(python_bin, field="session Python binary")
    _absolute_binary(systemctl_bin, field="session systemctl binary")
    systemd_run_bin = str(pathlib.PurePosixPath(systemctl_bin).with_name("systemd-run"))
    _absolute_binary(systemd_run_bin, field="session systemd-run binary")

    network_args, network_service = _network_args(effective, service_id, service)
    storage_args, volume_templates, requires_user = _storage_projection(effective, service)
    requires, after = _dependency_units(effective, service_id, service)
    target = _session_target(service_id)
    requires.append(target)
    after.append(target)
    if network_service is not None:
        requires.append(network_service)
        after.append(network_service)
    return {
        "schemaVersion": 2,
        "serviceId": service_id,
        "podman": podman_bin,
        "systemctl": systemctl_bin,
        "systemdRun": systemd_run_bin,
        "python": python_bin,
        "runner": str(source_dir / "nas_v2_session.py"),
        "targetUnit": target,
        "requires": sorted(set(requires)),
        "after": sorted(set(after)),
        "requiresUser": requires_user,
        "image": runtime["image"],
        "command": runtime["command"],
        "runArgs": [
            f"--pull={runtime['pull']}",
            *network_args,
            *storage_args,
            *_credential_args(effective, service),
            *_resource_args(service),
            *_sandbox_args(service),
        ],
        "volumeTemplates": volume_templates,
    }


def _target_unit(service_id: str) -> bytes:
    return (
        "\n".join(
            [
                "[Unit]",
                f"Description=Managed Services V2 session group for {service_id}",
                "StopWhenUnneeded=yes",
                "",
            ]
        )
    ).encode()


def _filtered_effective(effective: dict[str, Any], session_ids: set[str]) -> dict[str, Any]:
    filtered = copy.deepcopy(effective)
    filtered["services"] = {
        service_id: service for service_id, service in filtered["services"].items() if service_id not in session_ids
    }
    for service_id, service in filtered["services"].items():
        for dependency in service["dependencies"]:
            if dependency["service"] in session_ids:
                raise SessionProjectionError(
                    f"non-session service {service_id!r} may not depend on session template {dependency['service']!r}"
                )
    return filtered


def generate_projection(
    effective: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    python_bin: str,
    source_dir: pathlib.Path,
    systemctl_bin: str,
    uv_bin: str,
    podman_bin: str = "podman",
    compose_provider_bin: str = "podman-compose",
    virsh_bin: str = "virsh",
) -> tuple[dict[pathlib.Path, bytes], dict[str, Any]]:
    """Generate normal V2 units plus descriptors/targets for transient sessions."""
    session_ids = {
        service_id for service_id, service in effective["services"].items() if service["workload"]["kind"] == "session"
    }
    filtered = _filtered_effective(effective, session_ids)
    files, manifest = generate_base_projection(
        filtered,
        output_dir=output_dir,
        python_bin=python_bin,
        source_dir=source_dir,
        systemctl_bin=systemctl_bin,
        uv_bin=uv_bin,
        podman_bin=podman_bin,
        compose_provider_bin=compose_provider_bin,
        virsh_bin=virsh_bin,
    )

    links = manifest["links"]
    owned = set(manifest["ownedUnits"])
    stop = set(manifest["stopUnits"])
    fingerprints = manifest["fingerprints"]
    descriptor_dir = output_dir / "descriptors"
    unit_dir = output_dir / "units"

    for service_id in sorted(session_ids):
        service = effective["services"][service_id]
        if not service["managed"]:
            continue
        target = _session_target(service_id)
        if not service["enabled"]:
            stop.add(target)
            continue
        descriptor = _descriptor(
            effective,
            service_id,
            service,
            python_bin=python_bin,
            source_dir=source_dir,
            systemctl_bin=systemctl_bin,
            podman_bin=podman_bin,
        )
        descriptor_path = descriptor_dir / f"{service_id}.session.json"
        files[descriptor_path] = _json_bytes(descriptor)
        target_path = unit_dir / target
        files[target_path] = _target_unit(service_id)
        links.append({"target": target, "source": str(target_path)})
        owned.add(target)
        fingerprints[target] = _fingerprint(
            {
                "runtime": service["runtime"],
                "dependencies": service["dependencies"],
                "resources": service["resources"],
                "sandbox": service["sandbox"],
                "storage": service["storage"],
                "credentials": service["credentials"],
                "network": service.get("network"),
                "networkProfile": service.get("networkProfile"),
                "requiresUser": descriptor["requiresUser"],
            }
        )

    manifest["links"] = sorted(links, key=lambda item: item["target"])
    manifest["ownedUnits"] = sorted(owned)
    manifest["stopUnits"] = sorted(stop)
    manifest["fingerprints"] = fingerprints
    files[output_dir / "manifest.json"] = _json_bytes(manifest)
    return files, manifest


__all__ = ["SessionProjectionError", "generate_projection"]
