#!/usr/bin/env python3
"""Lower Managed Services V2 host storage, credentials, and devices to systemd."""

from __future__ import annotations

import pathlib
import re
from typing import Any


class SystemdAttachmentError(RuntimeError):
    """Raised when an attachment cannot be represented safely by systemd."""


_SAFE_CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_PROTECTED_HOME_ROOTS = (
    pathlib.PurePosixPath("/home"),
    pathlib.PurePosixPath("/root"),
    pathlib.PurePosixPath("/run/user"),
)
_DEV_ROOT = pathlib.PurePosixPath("/dev")


def _quote(value: str) -> str:
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise SystemdAttachmentError("systemd attachment path contains a forbidden control character")
    return '"' + value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'


def _bind_path(value: str, *, field: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SystemdAttachmentError(f"{field} must be an absolute safe path")
    if ":" in value:
        raise SystemdAttachmentError(f"{field} may not contain ':'")
    return path


def _bind_value(source: pathlib.PurePosixPath, destination: pathlib.PurePosixPath) -> str:
    if source == destination:
        return str(source)
    return f"{source}:{destination}"


def _under(path: pathlib.PurePosixPath, root: pathlib.PurePosixPath) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _protect_home_conflict(service: dict[str, Any], destination: pathlib.PurePosixPath, *, label: str) -> None:
    if service.get("sandbox", {}).get("mode") == "strict" and any(
        _under(destination, root) for root in _PROTECTED_HOME_ROOTS
    ):
        raise SystemdAttachmentError(f"{label} {destination} conflicts with generated ProtectHome=yes sandboxing")


def _storage_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    resources = effective.get("storageResources", {})
    if not isinstance(resources, dict):
        raise SystemdAttachmentError("compiled storageResources must be an object")
    runtime = service.get("runtime", {})
    identity = runtime.get("identity", {}) if isinstance(runtime, dict) else {}
    generated_runtime = isinstance(runtime, dict) and runtime.get("type") in {"exec", "python"}
    dynamic_identity = generated_runtime and isinstance(identity, dict) and identity.get("mode") == "dynamic"

    lines: list[str] = []
    for attachment in service.get("storage", []):
        if not isinstance(attachment, dict):
            raise SystemdAttachmentError("compiled storage attachment is invalid")
        resource_id = attachment.get("resource")
        resource = resources.get(resource_id) if isinstance(resource_id, str) else None
        if not isinstance(resource, dict) or not isinstance(resource.get("path"), str):
            raise SystemdAttachmentError(f"storage resource {resource_id!r} is missing from effective state")
        source = _bind_path(resource["path"], field=f"storage resource {resource_id!r} path")
        mount_path = attachment.get("mountPath")
        if not isinstance(mount_path, str):
            raise SystemdAttachmentError("storage attachment mountPath is missing")
        destination = _bind_path(mount_path, field="storage attachment mountPath")
        _protect_home_conflict(service, destination, label="storage mount")
        access = attachment.get("access")
        value = _bind_value(source, destination)
        if access == "read":
            lines.append(f"BindReadOnlyPaths={_quote(value)}")
        elif access == "write":
            if dynamic_identity:
                raise SystemdAttachmentError(
                    "writable host storage requires runtime.identity.mode=existing; refusing DynamicUser writable bind"
                )
            lines.append(f"BindPaths={_quote(value)}")
        else:
            raise SystemdAttachmentError(f"unsupported storage access mode {access!r}")
    return lines


def _credential_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    credentials = effective.get("credentials", {})
    if not isinstance(credentials, dict):
        raise SystemdAttachmentError("compiled credentials must be an object")

    lines: list[str] = []
    seen_native_ids: set[str] = set()
    seen_mounts: set[str] = set()
    for attachment in service.get("credentials", []):
        if not isinstance(attachment, dict):
            raise SystemdAttachmentError("compiled credential attachment is invalid")
        credential_id = attachment.get("credential")
        credential = credentials.get(credential_id) if isinstance(credential_id, str) else None
        if not isinstance(credential, dict) or not isinstance(credential.get("path"), str):
            raise SystemdAttachmentError(f"credential {credential_id!r} is missing from effective state")
        source_path = _bind_path(credential["path"], field=f"credential {credential_id!r} path")
        required = credential.get("required") is not False
        use = attachment.get("use")

        if use == "environment-file":
            prefix = "" if required else "-"
            lines.append(f"EnvironmentFile={prefix}{_quote(str(source_path))}")
            continue

        if use == "native-reference":
            if not required:
                raise SystemdAttachmentError(
                    f"optional native-reference credential {credential_id!r} is not safely representable yet"
                )
            if not isinstance(credential_id, str) or not _SAFE_CREDENTIAL_ID.fullmatch(credential_id):
                raise SystemdAttachmentError(f"credential identifier {credential_id!r} is unsafe for LoadCredential=")
            if credential_id in seen_native_ids:
                raise SystemdAttachmentError(f"duplicate native credential identifier {credential_id!r}")
            seen_native_ids.add(credential_id)
            lines.append(f"LoadCredential={_quote(credential_id + ':' + str(source_path))}")
            continue

        if use == "file":
            mount_path = attachment.get("mountPath")
            if not isinstance(mount_path, str):
                raise SystemdAttachmentError(f"file credential {credential_id!r} requires mountPath")
            destination = _bind_path(mount_path, field=f"file credential {credential_id!r} mountPath")
            _protect_home_conflict(service, destination, label="credential mount")
            destination_text = str(destination)
            if destination_text in seen_mounts:
                raise SystemdAttachmentError(f"duplicate file credential mount target {destination_text!r}")
            seen_mounts.add(destination_text)
            source_text = str(source_path)
            if not required:
                source_text = "-" + source_text
            lines.append(f"BindReadOnlyPaths={_quote(source_text + ':' + destination_text)}")
            continue
        raise SystemdAttachmentError(f"unsupported credential use {use!r}")
    return lines


def _accelerator_lines(service: dict[str, Any]) -> list[str]:
    resources = service.get("resources", {})
    accelerators = resources.get("accelerators", []) if isinstance(resources, dict) else []
    if not accelerators:
        return []
    runtime = service.get("runtime", {})
    identity = runtime.get("identity", {}) if isinstance(runtime, dict) else {}
    if isinstance(runtime, dict) and runtime.get("type") in {"exec", "python"}:
        if isinstance(identity, dict) and identity.get("mode") == "dynamic":
            raise SystemdAttachmentError(
                "generated host workloads with GPU access require runtime.identity.mode=existing so device DAC/group access is explicit"
            )
    lines = ["DevicePolicy=closed"]
    seen: set[str] = set()
    for accelerator in accelerators:
        if not isinstance(accelerator, dict) or accelerator.get("mode") != "shared":
            raise SystemdAttachmentError("systemd accelerator request was not resolved to shared device access")
        device = accelerator.get("device")
        if not isinstance(device, str):
            raise SystemdAttachmentError("systemd accelerator request is missing a concrete device selector")
        path = _bind_path(device, field="accelerator device")
        try:
            path.relative_to(_DEV_ROOT)
        except ValueError as exc:
            raise SystemdAttachmentError("systemd accelerators must resolve to device nodes beneath /dev") from exc
        value = str(path)
        if value not in seen:
            lines.append(f"DeviceAllow={_quote(value + ' rw')}")
            seen.add(value)
    return lines


def attachment_lines(effective: dict[str, Any], service: dict[str, Any]) -> list[str]:
    """Return deterministic systemd [Service] directives for host attachments."""
    return [
        *_storage_lines(effective, service),
        *_credential_lines(effective, service),
        *_accelerator_lines(service),
    ]


__all__ = ["SystemdAttachmentError", "attachment_lines"]
