#!/usr/bin/env python3
"""Realize GUI-provided V2 session inputs into safe runtime storage mounts."""

from __future__ import annotations

import copy
import pathlib
import re
from typing import Any

USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class V2SessionInputError(RuntimeError):
    pass


def parse_input_values(values: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise V2SessionInputError(f"Session input must be NAME=RELATIVE_PATH, got {item!r}")
        name, value = item.split("=", 1)
        if not name or name in result:
            raise V2SessionInputError(f"Duplicate or empty session input {name!r}")
        result[name] = value
    return result


def _identity_root(resource: dict[str, Any], *, user: str | None, instance_id: str) -> pathlib.Path:
    scope = resource.get("scope", "system")
    if scope == "system":
        raw = resource["path"]
    else:
        template = resource.get("pathTemplate")
        if not isinstance(template, str):
            raise V2SessionInputError("Identity-scoped resource is missing pathTemplate")
        if scope == "user":
            if user is None or USER_RE.fullmatch(user) is None:
                raise V2SessionInputError("User-scoped session input requires a validated --user identity")
            raw = template.replace("{user}", user)
        elif scope == "instance":
            if USER_RE.fullmatch(instance_id) is None:
                raise V2SessionInputError("Invalid session instance id")
            raw = template.replace("{instance}", instance_id)
        else:
            raise V2SessionInputError(f"Unsupported storage resource scope {scope!r}")
    path = pathlib.Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise V2SessionInputError(f"Unsafe session resource root {raw!r}")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise V2SessionInputError(f"Session resource root is unavailable: {path}") from exc


def _selected_path(root: pathlib.Path, value: str, *, allow_subpath: bool) -> pathlib.Path:
    if value in {"", "."}:
        candidate = root
    else:
        relative = pathlib.PurePosixPath(value)
        if relative.is_absolute() or ".." in relative.parts or any(char in value for char in ("\x00", "\r", "\n")):
            raise V2SessionInputError(f"Session input path must be a safe relative subpath, got {value!r}")
        if not allow_subpath:
            raise V2SessionInputError("This session input does not allow selecting a subpath")
        candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise V2SessionInputError(f"Session input escapes or does not exist beneath {root}: {value!r}") from exc
    return resolved


def realize_session_service(
    service_id: str,
    session_id: str,
    document: dict[str, Any],
    *,
    values: dict[str, str] | None = None,
    user: str | None = None,
) -> dict[str, Any]:
    service = document.get("services", {}).get(service_id)
    if not isinstance(service, dict):
        raise V2SessionInputError(f"Unknown V2 service {service_id!r}")
    if service.get("workload", {}).get("kind") != "session":
        raise V2SessionInputError(f"Service {service_id!r} is not a session workload")
    supplied = values or {}
    definitions = service.get("sessionInputs", {})
    if not isinstance(definitions, dict):
        raise V2SessionInputError(f"Service {service_id}: sessionInputs must be an object")
    unknown = sorted(set(supplied) - set(definitions))
    if unknown:
        raise V2SessionInputError(f"Service {service_id}: unknown session input(s) {unknown}")

    realized = copy.deepcopy(service)
    mounts = list(realized.get("resolvedStorage") or [])
    resources = document.get("storageResources", {})
    for input_id, definition in definitions.items():
        resource_id = definition["resource"]
        resource = resources.get(resource_id)
        if not isinstance(resource, dict):
            raise V2SessionInputError(f"Service {service_id} input {input_id}: unknown storage resource {resource_id!r}")
        root = _identity_root(resource, user=user, instance_id=session_id)
        value = supplied.get(input_id, ".")
        selected = _selected_path(root, value, allow_subpath=bool(definition.get("allowSubpath", True)))
        mount = {
            "resource": resource_id,
            "hostPath": str(selected),
            "guestPath": definition["mountPath"],
            "mode": "rw" if definition.get("access", "read") == "write" else "ro",
            "requiredCapabilities": [definition.get("access", "read")],
            "stateClass": resource["stateClass"],
            "scope": resource.get("scope", "system"),
            "sessionInput": input_id,
        }
        if definition.get("target") is not None:
            mount["target"] = definition["target"]
        mounts.append(mount)
    realized["resolvedStorage"] = mounts
    return realized


def decorate_document_for_session(
    service_id: str,
    session_id: str,
    document: dict[str, Any],
    *,
    values: dict[str, str] | None = None,
    user: str | None = None,
) -> dict[str, Any]:
    decorated = copy.deepcopy(document)
    decorated["services"][service_id] = realize_session_service(
        service_id,
        session_id,
        document,
        values=values,
        user=user,
    )
    return decorated
