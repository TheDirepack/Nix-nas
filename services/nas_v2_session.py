#!/usr/bin/env python3
"""Finite transient direct-OCI session runtime for Managed Services V2.

This helper contains no authorization or session database. An authenticated
caller supplies a service, instance, and (when user-scoped resources require
it) a user identifier. ``systemd-run`` creates one transient service whose
exec process is Podman itself; systemd owns termination (``KillMode=mixed``)
and cleanup (``ExecStopPost``), so no long-running supervisor process exists.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

from nas_v2_accelerator import is_cdi_selector
from nas_v2_network import (
    PodmanNetworkProjectionError,
    podman_network_name,
    quadlet_network_reference,
)
from nas_v2_systemd_native import generate_projection as generate_base_projection


class SessionError(RuntimeError):
    """Raised when a session action cannot be performed safely."""


_SERVICE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_INSTANCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_USER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")
_SYSTEMD_UNIT = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|target)$")
DEFAULT_PROJECTION_ROOT = pathlib.Path(os.environ.get("NAS_V2_PROJECTION_ROOT", "/run/nas-control/systemd"))


def validate_service_id(value: str) -> str:
    if not _SERVICE_ID.fullmatch(value):
        raise SessionError("invalid Managed Services V2 session service identifier")
    return value


def validate_instance_id(value: str) -> str:
    if not _INSTANCE_ID.fullmatch(value):
        raise SessionError("session instance identifier must match [a-z0-9][a-z0-9-]{0,47}")
    return value


def validate_user_id(value: str) -> str:
    if value in {".", ".."} or not _USER_ID.fullmatch(value):
        raise SessionError("session user identifier contains unsafe path/systemd characters")
    return value


def _user_key(user_id: str | None) -> str | None:
    if user_id is None:
        return None
    return hashlib.sha256(validate_user_id(user_id).encode("utf-8")).hexdigest()[:12]


def unit_name(service_id: str, instance_id: str, user_id: str | None = None) -> str:
    service_id = validate_service_id(service_id)
    instance_id = validate_instance_id(instance_id)
    key = _user_key(user_id)
    prefix = f"nas-v2-session-{service_id}" if key is None else f"nas-v2-session-{service_id}-u{key}"
    return f"{prefix}@{instance_id}.service"


def container_name(service_id: str, instance_id: str, user_id: str | None = None) -> str:
    service_id = validate_service_id(service_id)
    instance_id = validate_instance_id(instance_id)
    key = _user_key(user_id)
    suffix = instance_id if key is None else f"u{key}-{instance_id}"
    return f"nas-v2-session-{service_id}-{suffix}"


def descriptor_path(service_id: str, projection_root: pathlib.Path = DEFAULT_PROJECTION_ROOT) -> pathlib.Path:
    return projection_root / "descriptors" / f"{validate_service_id(service_id)}.session.json"


def _safe_path(value: str, *, field: str) -> pathlib.Path:
    if any(character in value for character in ("\x00", "\r", "\n", ":")):
        raise SessionError(f"{field} contains a forbidden character")
    path = pathlib.Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SessionError(f"{field} must be an absolute path without '..'")
    return path


def _safe_binary(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise SessionError(f"{field} is missing")
    return str(_safe_path(value, field=field))


def _safe_unit(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _SYSTEMD_UNIT.fullmatch(value):
        raise SessionError(f"{field} contains an invalid systemd unit name")
    return value


def _validate_volume_templates(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SessionError("session descriptor volumeTemplates must be an array")
    result: list[dict[str, str]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise SessionError("session descriptor volume template is invalid")
        root = entry.get("root")
        template = entry.get("sourceTemplate")
        target = entry.get("target")
        access = entry.get("access")
        scope = entry.get("scope")
        if (
            not isinstance(root, str)
            or not isinstance(template, str)
            or not isinstance(target, str)
            or not isinstance(access, str)
            or access not in {"ro", "rw"}
            or not isinstance(scope, str)
            or scope not in {"instance", "user"}
        ):
            raise SessionError("session descriptor volume template fields are invalid")
        token = "{instance}" if scope == "instance" else "{user}"
        if token not in template:
            raise SessionError("session descriptor volume template fields are invalid")
        _safe_path(root, field="session volume root")
        _safe_path(target, field="session volume target")
        probe = template.replace(token, "probe")
        if "{" in probe or "}" in probe:
            raise SessionError("session descriptor volume template contains an unsupported placeholder")
        _safe_path(probe, field="session volume pathTemplate")
        result.append(
            {
                "root": root,
                "sourceTemplate": template,
                "target": target,
                "access": access,
                "scope": scope,
            }
        )
    return result


def _load_descriptor(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"unable to read session descriptor {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 3:
        raise SessionError("session descriptor is invalid")
    service_id = value.get("serviceId")
    image = value.get("image")
    run_args = value.get("runArgs")
    command = value.get("command")
    requires = value.get("requires")
    after = value.get("after")
    if (
        not isinstance(service_id, str)
        or not isinstance(image, str)
        or not isinstance(run_args, list)
        or any(not isinstance(item, str) for item in run_args)
        or not isinstance(command, list)
        or any(not isinstance(item, str) for item in command)
        or not isinstance(requires, list)
        or not isinstance(after, list)
    ):
        raise SessionError("session descriptor fields are invalid")
    validate_service_id(service_id)
    for field in ("podman", "systemctl", "systemdRun"):
        value[field] = _safe_binary(value.get(field), field=f"session descriptor {field}")
    value["targetUnit"] = _safe_unit(value.get("targetUnit"), field="session targetUnit")
    value["requires"] = [_safe_unit(item, field="session requires") for item in requires]
    value["after"] = [_safe_unit(item, field="session after") for item in after]
    if not isinstance(value.get("requiresUser"), bool):
        raise SessionError("session descriptor requiresUser must be boolean")
    value["volumeTemplates"] = _validate_volume_templates(value.get("volumeTemplates"))
    return value


def _resolved_volume_args(descriptor: dict[str, Any], instance_id: str, user_id: str | None) -> list[str]:
    args: list[str] = []
    instance_id = validate_instance_id(instance_id)
    if user_id is not None:
        user_id = validate_user_id(user_id)
    if descriptor["requiresUser"] and user_id is None:
        raise SessionError("this session requires --user because it uses user-scoped storage")
    for entry in descriptor["volumeTemplates"]:
        template = entry["sourceTemplate"]
        if entry["scope"] == "instance":
            source_value = template.replace("{instance}", instance_id)
        else:
            if user_id is None:
                raise SessionError("user-scoped session volume cannot be resolved without --user")
            source_value = template.replace("{user}", user_id)
        if "{" in source_value or "}" in source_value:
            raise SessionError("session volume pathTemplate contains an unsupported placeholder")
        source = _safe_path(source_value, field="resolved session volume source")
        root = _safe_path(entry["root"], field="session volume root")
        target = _safe_path(entry["target"], field="session volume target")
        try:
            source.resolve(strict=False).relative_to(root.resolve(strict=False))
        except ValueError as exc:
            raise SessionError("resolved session volume source escapes its declared storage root") from exc
        args.extend(["--volume", f"{source}:{target}:{entry['access']}"])
    return args


def _run(command: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            stdin=None,
            stdout=None,
            stderr=None,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SessionError(f"unable to execute {command[0]}: {exc}") from exc


def _podman_run_command(
    descriptor: dict[str, Any],
    instance_id: str,
    user_id: str | None,
) -> list[str]:
    instance_id = validate_instance_id(instance_id)
    if user_id is not None:
        user_id = validate_user_id(user_id)
    if descriptor["requiresUser"] and user_id is None:
        raise SessionError("this session requires --user because it uses user-scoped storage")
    service_id = descriptor["serviceId"]
    name = container_name(service_id, instance_id, user_id)
    labels = [
        "--label",
        f"io.nixos-nas.v2.session={service_id}",
        "--label",
        f"io.nixos-nas.v2.instance={instance_id}",
    ]
    if user_id is not None:
        labels.extend(["--label", f"io.nixos-nas.v2.user={user_id}"])
    return [
        descriptor["podman"],
        "run",
        "--rm",
        "--name",
        name,
        *labels,
        *descriptor["runArgs"],
        *_resolved_volume_args(descriptor, instance_id, user_id),
        descriptor["image"],
        *descriptor["command"],
    ]


def stop_session(descriptor_path_value: pathlib.Path, instance_id: str, user_id: str | None = None) -> int:
    descriptor = _load_descriptor(descriptor_path_value)
    name = container_name(descriptor["serviceId"], instance_id, user_id)
    result = _run([descriptor["podman"], "stop", "--ignore", "--time", "10", name], timeout=30)
    return result.returncode


def cleanup_session(descriptor_path_value: pathlib.Path, instance_id: str, user_id: str | None = None) -> int:
    descriptor = _load_descriptor(descriptor_path_value)
    name = container_name(descriptor["serviceId"], instance_id, user_id)
    result = _run([descriptor["podman"], "rm", "--force", "--ignore", name], timeout=30)
    return result.returncode


def _transient_command(
    descriptor: dict[str, Any],
    descriptor_path_value: pathlib.Path,
    instance_id: str,
    user_id: str | None,
) -> list[str]:
    instance_id = validate_instance_id(instance_id)
    if descriptor["requiresUser"]:
        if user_id is None:
            raise SessionError("this session requires --user because it uses user-scoped storage")
        user_id = validate_user_id(user_id)
    elif user_id is not None:
        user_id = validate_user_id(user_id)
    unit = unit_name(descriptor["serviceId"], instance_id, user_id)
    run = _podman_run_command(descriptor, instance_id, user_id)
    command = [
        descriptor["systemdRun"],
        "--unit",
        unit,
        "--collect",
        "--quiet",
        "--service-type=exec",
        f"--property=Requires={' '.join(descriptor['requires'])}",
        f"--property=After={' '.join(descriptor['after'])}",
        f"--property=PartOf={descriptor['targetUnit']}",
        "--property=KillMode=mixed",
        "--property=TimeoutStopSec=45s",
        "--property=Restart=no",
        # systemd performs the container cleanup that the removed Python
        # supervisor used to perform in a ``finally`` block.
        f"--property=ExecStopPost={descriptor['podman']} rm --force --ignore "
        f"{container_name(descriptor['serviceId'], instance_id, user_id)}",
        "--",
        *run,
    ]
    if user_id is not None:
        command.extend(["--user", user_id])
    return command


def start_transient(
    descriptor_path_value: pathlib.Path,
    instance_id: str,
    user_id: str | None = None,
) -> int:
    descriptor = _load_descriptor(descriptor_path_value)
    return _run(_transient_command(descriptor, descriptor_path_value, instance_id, user_id), timeout=180).returncode


def stop_transient(
    descriptor_path_value: pathlib.Path,
    instance_id: str,
    user_id: str | None = None,
) -> int:
    descriptor = _load_descriptor(descriptor_path_value)
    if descriptor["requiresUser"] and user_id is None:
        raise SessionError("this session requires --user because it uses user-scoped storage")
    if user_id is not None:
        user_id = validate_user_id(user_id)
    unit = unit_name(descriptor["serviceId"], instance_id, user_id)
    stopped = _run([descriptor["systemctl"], "stop", unit], timeout=180)
    cleaned = cleanup_session(descriptor_path_value, instance_id, user_id)
    return stopped.returncode if stopped.returncode != 0 else cleaned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    for command in ("stop", "cleanup"):
        child = sub.add_parser(command)
        child.add_argument("--config", required=True)
        child.add_argument("--instance", required=True)
        child.add_argument("--user")

    for command in ("start", "stop-instance", "restart"):
        child = sub.add_parser(command)
        child.add_argument("service")
        child.add_argument("instance")
        child.add_argument("--user")
        child.add_argument("--projection-root", default=str(DEFAULT_PROJECTION_ROOT))

    args = parser.parse_args(argv)
    try:
        if args.command == "stop":
            return stop_session(pathlib.Path(args.config), args.instance, args.user)
        if args.command == "cleanup":
            return cleanup_session(pathlib.Path(args.config), args.instance, args.user)
        config = descriptor_path(args.service, pathlib.Path(args.projection_root))
        if args.command == "start":
            return start_transient(config, args.instance, args.user)
        if args.command == "stop-instance":
            return stop_transient(config, args.instance, args.user)
        stopped = stop_transient(config, args.instance, args.user)
        if stopped not in {0, 5}:
            return stopped
        return start_transient(config, args.instance, args.user)
    except SessionError as exc:
        print(f"nas-v2-session: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


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
        "schemaVersion": 3,
        "serviceId": service_id,
        "podman": podman_bin,
        "systemctl": systemctl_bin,
        "systemdRun": systemd_run_bin,
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
