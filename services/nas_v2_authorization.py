#!/usr/bin/env python3
"""Derive service-scoped Managed Services V2 authorization capabilities.

V2 does not authorize users. Authentik owns users, groups, MFA, memberships and
capability assignments; Caddy enforces those assignments at request time. V2
only publishes stable capability names while compiling service configuration.
"""

from __future__ import annotations

import re
from typing import Any

TOKEN_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
CAPABILITY_RE = re.compile(
    r"^v2\.service\.([a-z][a-z0-9-]{0,47})\.([a-z][a-z0-9-]{0,47})$"
)


class V2AuthorizationError(RuntimeError):
    pass


def _token(value: str, *, field: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise V2AuthorizationError(f"Invalid {field} {value!r}")
    return value


def service_capability(service_id: str, capability_id: str = "access") -> str:
    return f"v2.service.{_token(service_id, field='service id')}.{_token(capability_id, field='capability id')}"


def validate_capability(value: Any, *, service_id: str | None = None) -> str:
    if not isinstance(value, str):
        raise V2AuthorizationError(f"Invalid V2 authorization capability {value!r}")
    match = CAPABILITY_RE.fullmatch(value)
    if match is None:
        raise V2AuthorizationError(f"Invalid V2 authorization capability {value!r}")
    if service_id is not None and match.group(1) != service_id:
        raise V2AuthorizationError(
            f"Capability {value!r} belongs to service {match.group(1)!r}, not {service_id!r}"
        )
    return value


def capability_group_name(value: str) -> str:
    validate_capability(value)
    return "nas_" + value.replace(".", "_").replace("-", "_")


def route_capability(service_id: str, route: dict[str, Any]) -> str | None:
    """Return the service capability an identity-protected route requires.

    Routes do not create a separate authorization namespace. An identity route
    either names one service capability explicitly or uses the service's
    automatic ``access`` capability.
    """

    auth = route.get("auth") or {}
    if not isinstance(auth, dict) or auth.get("mode") != "identity":
        return None
    explicit = auth.get("capability")
    if explicit is None:
        return service_capability(service_id, "access")
    return validate_capability(explicit, service_id=service_id)


def desired_capabilities(document: dict[str, Any]) -> set[str]:
    """Return service capabilities that Authentik should expose for assignment."""

    desired: set[str] = set()
    services = document.get("services") or {}
    if not isinstance(services, dict):
        raise V2AuthorizationError("services must be an object")

    for service_id, service in services.items():
        _token(service_id, field="service id")
        if not isinstance(service, dict):
            continue
        desired.add(service_capability(service_id, "access"))
        for route in (service.get("routes") or {}).values():
            if not isinstance(route, dict):
                continue
            required = route_capability(service_id, route)
            if required is not None:
                desired.add(required)
    return desired
