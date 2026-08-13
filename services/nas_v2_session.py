#!/usr/bin/env python3
"""Finite transient direct-OCI session runtime for Managed Services V2.

This helper contains no authorization or session database. An authenticated
caller supplies a service, instance, and (when user-scoped resources require
it) a user identifier. ``systemd-run`` creates one transient service; Podman
owns the container and the helper performs stop/cleanup on termination.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
from typing import Any


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
    if not isinstance(value, dict) or value.get("schemaVersion") != 2:
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
    for field in ("podman", "systemctl", "systemdRun", "python", "runner"):
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


def _podman_commands(
    descriptor: dict[str, Any],
    instance_id: str,
    user_id: str | None,
) -> tuple[list[str], list[str], list[str]]:
    instance_id = validate_instance_id(instance_id)
    if user_id is not None:
        user_id = validate_user_id(user_id)
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
    run = [
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
    stop = [descriptor["podman"], "stop", "--ignore", "--time", "10", name]
    cleanup = [descriptor["podman"], "rm", "--force", "--ignore", name]
    return run, stop, cleanup


def run_session(descriptor_path_value: pathlib.Path, instance_id: str, user_id: str | None = None) -> int:
    descriptor = _load_descriptor(descriptor_path_value)
    run, stop, cleanup = _podman_commands(descriptor, instance_id, user_id)
    try:
        process = subprocess.Popen(run, stdin=None, stdout=None, stderr=None, text=True)
    except OSError as exc:
        raise SessionError(f"unable to execute {run[0]}: {exc}") from exc

    previous: dict[int, Any] = {}

    def terminate(_signum: int, _frame: Any) -> None:
        _run(stop, timeout=30)

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, terminate)
        return process.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        _run(cleanup, timeout=30)


def stop_session(descriptor_path_value: pathlib.Path, instance_id: str, user_id: str | None = None) -> int:
    descriptor = _load_descriptor(descriptor_path_value)
    _run_command, stop, _cleanup = _podman_commands(descriptor, instance_id, user_id)
    result = _run(stop, timeout=30)
    return result.returncode


def cleanup_session(descriptor_path_value: pathlib.Path, instance_id: str, user_id: str | None = None) -> int:
    descriptor = _load_descriptor(descriptor_path_value)
    _run_command, _stop, cleanup = _podman_commands(descriptor, instance_id, user_id)
    result = _run(cleanup, timeout=30)
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
        "--",
        descriptor["python"],
        descriptor["runner"],
        "run",
        "--config",
        str(descriptor_path_value),
        "--instance",
        instance_id,
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

    for command in ("run", "stop", "cleanup"):
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
        if args.command == "run":
            return run_session(pathlib.Path(args.config), args.instance, args.user)
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
