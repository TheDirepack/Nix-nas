#!/usr/bin/env python3
"""Render deterministic Compose overrides for Managed Services V2.

Compose remains the container-definition authority. V2 contributes generic
cross-cutting policy: storage, credentials, resources, sandboxing, devices, and
network intent. Lifecycle is lowered separately into systemd.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from nas_v2_accelerator import is_cdi_selector


class ComposeProjectionError(RuntimeError):
    """Raised when V2 policy cannot be faithfully represented by Compose."""


APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
_NETWORK_KEY = "nas_v2"
_STRICT_SOURCE_FIELDS = frozenset(
    {
        "cap_add",
        "cap_drop",
        "cgroup",
        "cgroup_parent",
        "device_cgroup_rules",
        "devices",
        "ipc",
        "pid",
        "privileged",
        "read_only",
        "security_opt",
        "tmpfs",
        "userns_mode",
        "uts",
        "volumes_from",
    }
)


def _source(service_id: str, service: dict[str, Any]) -> tuple[pathlib.Path, dict[str, dict[str, Any]]]:
    raw = service["runtime"]["source"]
    candidate = pathlib.Path(raw)
    if candidate.suffix not in {".yaml", ".yml"}:
        raise ComposeProjectionError(f"Compose service {service_id!r} source must be a YAML file")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to((APP_ROOT / service_id).resolve(strict=False))
    except (OSError, ValueError) as exc:
        raise ComposeProjectionError(
            f"Compose service {service_id!r} source must exist beneath its managed app root"
        ) from exc
    if not resolved.is_file():
        raise ComposeProjectionError(f"Compose service {service_id!r} source must name a file")

    parser = YAML(typ="safe", pure=True)
    parser.version = (1, 2)
    parser.allow_duplicate_keys = False
    try:
        document = parser.load(resolved.read_text(encoding="utf-8"))
    except (OSError, YAMLError) as exc:
        raise ComposeProjectionError(f"unable to parse Compose source for {service_id!r}: {exc}") from exc
    raw_services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(raw_services, dict) or not raw_services:
        raise ComposeProjectionError(f"Compose service {service_id!r} source must define a non-empty services mapping")
    services: dict[str, dict[str, Any]] = {}
    for name, definition in raw_services.items():
        if not isinstance(name, str) or not name or not isinstance(definition, dict):
            raise ComposeProjectionError(f"Compose service {service_id!r} contains an invalid service definition")
        services[name] = definition
    return resolved, services


def _target(overrides: dict[str, dict[str, Any]], names: set[str], target: Any) -> dict[str, Any]:
    if not isinstance(target, str) or target not in names:
        raise ComposeProjectionError(f"Compose attachment target {target!r} does not exist in the Compose source")
    return overrides.setdefault(target, {})


def _network_policy(effective: dict[str, Any], service: dict[str, Any]) -> dict[str, Any] | None:
    if "network" in service:
        return service["network"]
    profile = service.get("networkProfile")
    if profile is None:
        return None
    policy = effective.get("networkProfiles", {}).get(profile)
    if not isinstance(policy, dict):
        raise ComposeProjectionError(f"compiled network profile {profile!r} is missing")
    return policy


def _reject_source_networks(service_id: str, source_services: dict[str, dict[str, Any]]) -> None:
    for name, definition in source_services.items():
        if "network_mode" in definition or "networks" in definition:
            raise ComposeProjectionError(
                f"Compose service {service_id!r} source service {name!r} declares networking while V2 network policy is authoritative"
            )


def _compose_capability(value: str) -> str:
    return value.removeprefix("CAP_")


def _apply_resource_policy(
    service: dict[str, Any],
    service_names: set[str],
    overrides: dict[str, dict[str, Any]],
) -> None:
    resources = service["resources"]
    cpu = resources.get("cpuQuotaPercent")
    memory_high = resources.get("memoryHighBytes")
    memory_max = resources.get("memoryMaxBytes")
    pids = resources.get("pidsMax")
    if all(value is None for value in (cpu, memory_high, memory_max, pids)):
        return
    for name in service_names:
        destination = overrides.setdefault(name, {})
        if cpu is not None:
            destination["cpus"] = cpu / 100
        if memory_high is not None:
            destination["mem_reservation"] = str(memory_high)
        if memory_max is not None:
            destination["mem_limit"] = str(memory_max)
        if pids is not None:
            destination["pids_limit"] = pids


def _apply_sandbox_policy(
    service_id: str,
    service: dict[str, Any],
    source_services: dict[str, dict[str, Any]],
    overrides: dict[str, dict[str, Any]],
) -> None:
    sandbox = service["sandbox"]
    if sandbox["mode"] == "inherit":
        return
    if sandbox.get("writablePaths"):
        raise ComposeProjectionError(
            f"Compose service {service_id!r} strict sandbox writablePaths must use explicit storage or tmpfs attachments"
        )

    for name, source in source_services.items():
        conflicts = sorted(_STRICT_SOURCE_FIELDS.intersection(source))
        if conflicts:
            raise ComposeProjectionError(
                f"Compose service {service_id!r} source service {name!r} declares security fields that conflict with V2 strict sandboxing: "
                + ", ".join(conflicts)
            )

    read_only = sandbox.get("readOnlyRoot", True)
    no_new_privileges = sandbox.get("noNewPrivileges", True)
    cap_add = [_compose_capability(value) for value in sandbox.get("addCapabilities", [])]
    cap_drop = [_compose_capability(value) for value in sandbox.get("dropCapabilities", [])]
    tmpfs = sandbox.get("tmpfs", [])

    for name in source_services:
        destination = overrides.setdefault(name, {})
        destination["privileged"] = False
        destination["read_only"] = read_only
        if no_new_privileges:
            destination["security_opt"] = ["no-new-privileges"]
        if cap_add:
            destination["cap_add"] = cap_add
        if cap_drop:
            destination["cap_drop"] = cap_drop
        for entry in tmpfs:
            mount: dict[str, Any] = {
                "type": "tmpfs",
                "target": entry["path"],
            }
            if "sizeBytes" in entry:
                mount["tmpfs"] = {"size": entry["sizeBytes"]}
            destination.setdefault("volumes", []).append(mount)


def _apply_accelerators(
    service_id: str,
    service: dict[str, Any],
    service_names: set[str],
    overrides: dict[str, dict[str, Any]],
) -> None:
    for accelerator in service["resources"]["accelerators"]:
        destination = _target(overrides, service_names, accelerator.get("target"))
        device = accelerator.get("device")
        if accelerator["mode"] != "shared" or not isinstance(device, str):
            raise ComposeProjectionError(f"Compose service {service_id!r} has an unresolved GPU request")
        if not device.startswith("/dev/") and not is_cdi_selector(device):
            raise ComposeProjectionError(
                f"Compose service {service_id!r} accelerator selector {device!r} is neither a device path nor CDI selector"
            )
        destination.setdefault("devices", []).append(device)


def render_compose_override(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
) -> tuple[pathlib.Path, bytes]:
    """Return the validated source path and a deterministic Compose override."""
    if service["runtime"]["type"] != "compose":
        raise ComposeProjectionError(f"service {service_id!r} is not a Compose runtime")
    if service["workload"]["kind"] != "daemon":
        raise ComposeProjectionError(f"Compose service {service_id!r} currently supports daemon workloads only")
    source, source_services = _source(service_id, service)
    service_names = set(source_services)
    overrides: dict[str, dict[str, Any]] = {}

    _apply_resource_policy(service, service_names, overrides)
    _apply_sandbox_policy(service_id, service, source_services, overrides)

    resources = effective.get("storageResources", {})
    for attachment in service["storage"]:
        destination = _target(overrides, service_names, attachment.get("target"))
        resource = resources.get(attachment["resource"])
        if not isinstance(resource, dict) or not isinstance(resource.get("path"), str):
            raise ComposeProjectionError(f"compiled storage resource {attachment['resource']!r} is missing")
        volume = {
            "type": "bind",
            "source": resource["path"],
            "target": attachment["mountPath"],
            "read_only": attachment["access"] == "read",
            "bind": {"create_host_path": False},
        }
        destination.setdefault("volumes", []).append(volume)

    credentials = effective.get("credentials", {})
    for attachment in service["credentials"]:
        destination = _target(overrides, service_names, attachment.get("target"))
        credential = credentials.get(attachment["credential"])
        if not isinstance(credential, dict) or not isinstance(credential.get("path"), str):
            raise ComposeProjectionError(f"compiled credential {attachment['credential']!r} is missing")
        if credential.get("required", True) is not True:
            raise ComposeProjectionError(
                f"optional Compose credential {attachment['credential']!r} is not representable without provider-specific behavior"
            )
        use = attachment["use"]
        if use == "file":
            mount = attachment.get("mountPath")
            if not isinstance(mount, str):
                raise ComposeProjectionError("Compose file credentials require mountPath")
            destination.setdefault("volumes", []).append(
                {
                    "type": "bind",
                    "source": credential["path"],
                    "target": mount,
                    "read_only": True,
                    "bind": {"create_host_path": False},
                }
            )
        elif use == "environment-file":
            destination.setdefault("env_file", []).append(credential["path"])
        else:
            raise ComposeProjectionError(f"Compose credential use {use!r} is not implemented")

    _apply_accelerators(service_id, service, service_names, overrides)

    top_level: dict[str, Any] = {}
    policy = _network_policy(effective, service)
    if policy is not None:
        _reject_source_networks(service_id, source_services)
        mode = policy["mode"]
        has_fixed_ingress = bool(service.get("routes")) or bool(service.get("listeners"))
        if mode == "isolated":
            if has_fixed_ingress:
                raise ComposeProjectionError(
                    f"Compose service {service_id!r} cannot expose V2 routes/listeners while V3 lacks a target container selector"
                )
            for name in service_names:
                overrides.setdefault(name, {})["networks"] = [_NETWORK_KEY]
            top_level["networks"] = {
                _NETWORK_KEY: {
                    "external": True,
                    "name": f"nas-v2-{service_id}",
                }
            }
        elif mode == "host":
            if (
                policy["outboundDefault"] != "allow"
                or policy["allowedEgress"]
                or not policy["lanAccess"]
                or policy["allowedHostPorts"]
            ):
                raise ComposeProjectionError(
                    f"Compose service {service_id!r} host networking cannot enforce the requested restrictions"
                )
            for name in service_names:
                overrides.setdefault(name, {})["network_mode"] = "host"
        elif mode == "none":
            if policy["allowedEgress"] or policy["allowedHostPorts"] or policy["lanAccess"]:
                raise ComposeProjectionError(
                    f"Compose service {service_id!r} network mode none cannot include network exceptions"
                )
            if has_fixed_ingress:
                raise ComposeProjectionError(
                    f"Compose service {service_id!r} network mode none cannot expose routes/listeners"
                )
            for name in service_names:
                overrides.setdefault(name, {})["network_mode"] = "none"
        else:
            raise ComposeProjectionError(f"Compose service {service_id!r} has unsupported network mode {mode!r}")

    document: dict[str, Any] = {"services": {name: overrides[name] for name in sorted(overrides)}}
    document.update(top_level)
    return source, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


__all__ = ["ComposeProjectionError", "render_compose_override"]
