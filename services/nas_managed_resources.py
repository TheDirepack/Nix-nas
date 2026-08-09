#!/usr/bin/env python3
"""Shared Managed Services V2 resource and authorization model helpers.

This module deliberately contains no daemon or persistence layer. It validates
and normalizes the cross-system policy that V2 owns; Authentik remains the
source of authorization assignments and runtime adapters remain responsible
for enforcing the resulting mounts/network policy.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

ALLOWED_HOST_ROOTS = ("/tank", "/srv", "/var/lib/nas-control/apps")
RESOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
RUNTIME_TARGET_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
APPLICATION_PRINCIPAL_RE = re.compile(r"^application:([a-z][a-z0-9-]{0,47})$")
CAPABILITY_RE = re.compile(r"^(application|storage)\.([a-z][a-z0-9-]{0,47})\.([a-z][a-z0-9-]{0,47})$")
STATE_CLASSES = frozenset({"authoritative", "derived", "cache", "ephemeral"})
STORAGE_CAPABILITIES = frozenset({"read", "write", "move", "delete", "admin"})
BACKUP_CONSISTENCY = frozenset({"filesystem", "zfs-snapshot", "postgres", "native", "none"})
RESOURCE_SCOPES = frozenset({"system", "user", "instance"})
UNSAFE_MOUNT_PATH_CHARS = frozenset({"\x00", "\r", "\n", ":"})


class ManagedResourceError(RuntimeError):
    """Raised when V2 resource policy is invalid."""


def validate_resource_id(value: Any) -> str:
    if not isinstance(value, str) or not RESOURCE_ID_RE.fullmatch(value):
        raise ManagedResourceError(f"Invalid resource ID {value!r}")
    return value


def application_principal(service_id: str) -> str:
    validate_resource_id(service_id)
    return f"application:{service_id}"


def validate_application_principal(value: Any, *, service_id: str | None = None) -> str:
    if not isinstance(value, str):
        raise ManagedResourceError("application principal must be a string")
    match = APPLICATION_PRINCIPAL_RE.fullmatch(value)
    if match is None:
        raise ManagedResourceError(f"Invalid application principal {value!r}")
    if service_id is not None and match.group(1) != service_id:
        raise ManagedResourceError(
            f"Application principal {value!r} does not match service {service_id!r}"
        )
    return value


def validate_capability_reference(value: Any) -> str:
    if not isinstance(value, str) or CAPABILITY_RE.fullmatch(value) is None:
        raise ManagedResourceError(f"Invalid authorization capability {value!r}")
    return value


def capability_group_name(capability: str) -> str:
    validate_capability_reference(capability)
    return "nas_" + capability.replace(".", "_").replace("-", "_")


def storage_capability(resource_id: str, capability: str) -> str:
    validate_resource_id(resource_id)
    if capability not in STORAGE_CAPABILITIES:
        raise ManagedResourceError(f"Unknown storage capability {capability!r}")
    return f"storage.{resource_id}.{capability}"


def application_capability(service_id: str, capability: str = "access") -> str:
    validate_resource_id(service_id)
    if not RESOURCE_ID_RE.fullmatch(capability):
        raise ManagedResourceError(f"Invalid application capability {capability!r}")
    return f"application.{service_id}.{capability}"


def _validate_mount_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ManagedResourceError(f"{field} must be an absolute path")
    if any(char in value for char in UNSAFE_MOUNT_PATH_CHARS):
        raise ManagedResourceError(f"{field} contains an unsafe mount delimiter or control character")
    pure = pathlib.PurePosixPath(value)
    if ".." in pure.parts:
        raise ManagedResourceError(f"{field} must not contain '..'")
    return value


def _validate_host_path(value: Any, *, field: str = "path") -> str:
    value = _validate_mount_path(value, field=field)
    if not any(value == root or value.startswith(root + "/") for root in ALLOWED_HOST_ROOTS):
        raise ManagedResourceError(f"{field} {value!r} is outside the managed storage roots")
    return value


def validate_storage_resource(resource_id: str, data: Any) -> dict[str, Any]:
    validate_resource_id(resource_id)
    if not isinstance(data, dict):
        raise ManagedResourceError(f"Storage resource {resource_id!r} must be an object")

    path = _validate_host_path(data.get("path"), field=f"storageResources.{resource_id}.path")
    scope = data.get("scope", "system")
    if scope not in RESOURCE_SCOPES:
        raise ManagedResourceError(f"Storage resource {resource_id!r}: invalid scope {scope!r}")

    path_template = data.get("pathTemplate")
    if scope == "user":
        if path_template is None:
            raise ManagedResourceError(f"Storage resource {resource_id!r}: user scope requires pathTemplate")
        _validate_host_path(path_template, field=f"storageResources.{resource_id}.pathTemplate")
        if "{user}" not in path_template:
            raise ManagedResourceError(
                f"Storage resource {resource_id!r}: user pathTemplate must contain '{{user}}'"
            )
    elif path_template is not None:
        _validate_host_path(path_template, field=f"storageResources.{resource_id}.pathTemplate")

    state_class = data.get("stateClass")
    if state_class not in STATE_CLASSES:
        raise ManagedResourceError(
            f"Storage resource {resource_id!r}: stateClass must be one of {sorted(STATE_CLASSES)}"
        )

    capabilities = data.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise ManagedResourceError(f"Storage resource {resource_id!r}: capabilities must be a non-empty array")
    if len(capabilities) != len(set(capabilities)):
        raise ManagedResourceError(f"Storage resource {resource_id!r}: duplicate capability")
    unknown = set(capabilities) - STORAGE_CAPABILITIES
    if unknown:
        raise ManagedResourceError(
            f"Storage resource {resource_id!r}: unsupported capabilities {sorted(unknown)}"
        )

    backup = data.get("backup")
    if not isinstance(backup, dict) or not isinstance(backup.get("enabled"), bool):
        raise ManagedResourceError(f"Storage resource {resource_id!r}: backup.enabled must be boolean")
    consistency = backup.get("consistency", "filesystem")
    if consistency not in BACKUP_CONSISTENCY:
        raise ManagedResourceError(
            f"Storage resource {resource_id!r}: invalid backup consistency {consistency!r}"
        )
    if state_class in {"cache", "ephemeral"} and backup.get("enabled"):
        raise ManagedResourceError(
            f"Storage resource {resource_id!r}: {state_class} state must not be selected for backup"
        )
    if consistency == "none" and backup.get("enabled"):
        raise ManagedResourceError(
            f"Storage resource {resource_id!r}: backup cannot be enabled with consistency='none'"
        )

    quota = data.get("quotaBytes")
    if quota is not None and (isinstance(quota, bool) or not isinstance(quota, int) or quota < 0):
        raise ManagedResourceError(f"Storage resource {resource_id!r}: quotaBytes must be a non-negative integer")

    normalized = dict(data)
    normalized["path"] = path
    normalized["scope"] = scope
    normalized["stateClass"] = state_class
    normalized["capabilities"] = list(capabilities)
    normalized["backup"] = {**backup, "consistency": consistency}
    return normalized


def validate_storage_resources(resources: Any) -> dict[str, dict[str, Any]]:
    if resources is None:
        return {}
    if not isinstance(resources, dict):
        raise ManagedResourceError("storageResources must be an object")
    return {resource_id: validate_storage_resource(resource_id, data) for resource_id, data in resources.items()}


def validate_storage_attachment(
    service_id: str,
    attachment: Any,
    resources: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Validate and normalize one resource-reference attachment."""

    validate_resource_id(service_id)
    if not isinstance(attachment, dict):
        raise ManagedResourceError(f"Service {service_id}: storage attachment must be an object")
    resource_id = validate_resource_id(attachment.get("resource"))
    if resource_id not in resources:
        raise ManagedResourceError(f"Service {service_id}: unknown storage resource {resource_id!r}")
    guest_path = _validate_mount_path(
        attachment.get("guestPath"),
        field=f"Service {service_id}: guestPath",
    )
    required = attachment.get("requiredCapabilities", ["read"])
    if not isinstance(required, list) or not required:
        raise ManagedResourceError(f"Service {service_id}: requiredCapabilities must be a non-empty array")
    if len(required) != len(set(required)):
        raise ManagedResourceError(f"Service {service_id}: duplicate required capability")
    unsupported = set(required) - set(resources[resource_id]["capabilities"])
    if unsupported:
        raise ManagedResourceError(
            f"Service {service_id}: resource {resource_id!r} does not expose capabilities {sorted(unsupported)}"
        )
    normalized = {
        "resource": resource_id,
        "guestPath": guest_path,
        "requiredCapabilities": list(required),
    }
    target = attachment.get("target")
    if target is not None:
        if not isinstance(target, str) or RUNTIME_TARGET_RE.fullmatch(target) is None:
            raise ManagedResourceError(f"Service {service_id}: invalid storage runtime target {target!r}")
        normalized["target"] = target
    return normalized


def backup_resource_ids(resources: dict[str, dict[str, Any]]) -> list[str]:
    selected = []
    for resource_id, resource in resources.items():
        if resource["backup"]["enabled"]:
            selected.append(resource_id)
    return sorted(selected)
