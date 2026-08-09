#!/usr/bin/env python3
"""Derive Managed Services V2 authorization capabilities from object identity.

V2 does not own users, groups, MFA, memberships, or identity validation.
Authentik is the authorization database.  This module only gives every V2
object a deterministic capability identity that the Authentik projection can
materialize as assignable groups.
"""

from __future__ import annotations

import re
from typing import Any

TOKEN_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
CAPABILITY_RE = re.compile(
    r"^v2\.(service|route|listener|storage|credential|network|session-input)\."
    r"([a-z][a-z0-9-]{0,47})(?:\.([a-z][a-z0-9-]{0,47}))?\."
    r"(access|use|manage|execute|read|write|move|delete|admin)$"
)


class V2AuthorizationError(RuntimeError):
    pass


def _token(value: str, *, field: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise V2AuthorizationError(f"Invalid {field} {value!r}")
    return value


def capability(kind: str, object_id: str, action: str, *, child_id: str | None = None) -> str:
    _token(object_id, field=f"{kind} object id")
    if child_id is not None:
        _token(child_id, field=f"{kind} child id")
    value = f"v2.{kind}.{object_id}"
    if child_id is not None:
        value += f".{child_id}"
    value += f".{action}"
    return validate_capability(value)


def validate_capability(value: Any) -> str:
    if not isinstance(value, str) or CAPABILITY_RE.fullmatch(value) is None:
        raise V2AuthorizationError(f"Invalid V2 authorization capability {value!r}")
    return value


def capability_group_name(value: str) -> str:
    validate_capability(value)
    return "nas_" + value.replace(".", "_").replace("-", "_")


def service_capability(service_id: str, action: str = "use") -> str:
    return capability("service", service_id, action)


def route_capability(service_id: str, route_id: str, action: str = "access") -> str:
    return capability("route", service_id, action, child_id=route_id)


def listener_capability(service_id: str, listener_id: str, action: str = "manage") -> str:
    return capability("listener", service_id, action, child_id=listener_id)


def session_input_capability(service_id: str, input_id: str, action: str = "use") -> str:
    return capability("session-input", service_id, action, child_id=input_id)


def desired_capabilities(document: dict[str, Any]) -> set[str]:
    """Return the complete assignable capability catalog for a V2 document."""

    desired: set[str] = set()

    for resource_id, resource in (document.get("storageResources") or {}).items():
        _token(resource_id, field="storage resource id")
        actions = resource.get("capabilities") if isinstance(resource, dict) else None
        if isinstance(actions, list):
            for action in actions:
                if action in {"read", "write", "move", "delete", "admin"}:
                    desired.add(capability("storage", resource_id, action))

    for credential_id in (document.get("credentials") or {}):
        desired.add(capability("credential", credential_id, "manage"))
        desired.add(capability("credential", credential_id, "use"))

    for profile_id in (document.get("networkProfiles") or {}):
        desired.add(capability("network", profile_id, "manage"))
        desired.add(capability("network", profile_id, "use"))

    for service_id, service in (document.get("services") or {}).items():
        if not isinstance(service, dict):
            continue
        desired.add(service_capability(service_id, "use"))
        desired.add(service_capability(service_id, "manage"))
        workload = service.get("workload") or {}
        if workload.get("kind") == "job":
            desired.add(service_capability(service_id, "execute"))
        if workload.get("kind") == "session":
            desired.add(service_capability(service_id, "access"))
        for route_id in (service.get("routes") or {}):
            desired.add(route_capability(service_id, route_id))
        for listener_id in (service.get("listeners") or {}):
            desired.add(listener_capability(service_id, listener_id))
        for input_id in (service.get("sessionInputs") or {}):
            desired.add(session_input_capability(service_id, input_id))

    return desired
