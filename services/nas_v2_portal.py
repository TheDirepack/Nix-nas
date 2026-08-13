#!/usr/bin/env python3
"""Generate the authenticated landing-page model from Managed Services V2.

The portal is a projection of the same desired/effective service model used by
Caddy. It is not a second endpoint registry or authorization authority. Caddy
still enforces every request; this projection only hides links the current
Authentik group header cannot use.
"""

from __future__ import annotations

import json
from typing import Any

ADMIN_GROUP = "nas_admin"


class PortalProjectionError(RuntimeError):
    """Raised when portal metadata cannot be projected safely."""


def _canonical_capability(service_id: str, capability: str) -> str:
    return f"application.{service_id}.{capability}"


def _route_url(exposure: dict[str, Any], portal: dict[str, Any]) -> str:
    explicit = portal.get("url")
    if isinstance(explicit, str) and explicit.startswith("/") and not explicit.startswith("//"):
        return explicit
    exposure_type = exposure.get("type")
    if exposure_type == "path":
        paths = exposure.get("paths")
        candidate = paths[0] if isinstance(paths, list) and paths and isinstance(paths[0], str) else None
        if isinstance(candidate, str) and candidate.startswith("/") and not candidate.startswith("//"):
            return candidate
        raise PortalProjectionError("visible portal path route has no safe path")
    if exposure_type == "hostname":
        hostnames = exposure.get("hostnames")
        path = exposure.get("path", "/")
        if (
            isinstance(hostnames, list)
            and hostnames
            and isinstance(hostnames[0], str)
            and isinstance(path, str)
            and path.startswith("/")
        ):
            return f"https://{hostnames[0]}{path}"
    raise PortalProjectionError("visible portal route has no safe URL")


def _access(service_id: str, route: dict[str, Any]) -> dict[str, Any]:
    auth = route.get("auth")
    if not isinstance(auth, dict):
        raise PortalProjectionError(f"route {service_id!r} has no normalized auth policy")
    mode = auth.get("mode")
    if mode == "identity":
        capability = auth.get("capability", "access")
        if not isinstance(capability, str) or not capability:
            raise PortalProjectionError(f"route {service_id!r} has an invalid capability")
        return {
            "mode": "groups",
            "allow": "groups",
            "groups": [_canonical_capability(service_id, capability), ADMIN_GROUP],
            "users": [],
        }
    if mode == "public":
        return {"mode": "public", "allow": "any", "groups": [], "users": []}
    if mode == "upstream":
        # The portal is already behind appliance authentication. Upstream-native
        # application auth remains authoritative after the user follows the link.
        return {"mode": "upstream", "allow": "any", "groups": [], "users": []}
    raise PortalProjectionError(f"route {service_id!r} has unsupported auth mode {mode!r}")


def compile_portal_projection(effective: dict[str, Any]) -> dict[str, Any]:
    if effective.get("schemaVersion") != 3:
        raise PortalProjectionError("effective state must use schema version 3")
    services = effective.get("services")
    if not isinstance(services, dict):
        raise PortalProjectionError("effective state is missing services")

    entries: list[dict[str, Any]] = []
    for service_id in sorted(services):
        service = services[service_id]
        if not isinstance(service, dict) or service.get("enabled", True) is False:
            continue
        routes = service.get("routes", {})
        if not isinstance(routes, dict):
            raise PortalProjectionError(f"service {service_id!r} has invalid routes")
        for route_id in sorted(routes):
            route = routes[route_id]
            if not isinstance(route, dict):
                continue
            portal = route.get("portal", {})
            if not isinstance(portal, dict) or portal.get("visible") is not True:
                continue
            exposure = route.get("exposure")
            if not isinstance(exposure, dict):
                raise PortalProjectionError(f"visible route {service_id}.{route_id} has invalid exposure")
            entries.append(
                {
                    "id": f"{service_id}.{route_id}",
                    "service": service_id,
                    "route": route_id,
                    "label": portal.get("title") or service.get("name") or service_id,
                    "description": portal.get("description") or service.get("description", ""),
                    "category": portal.get("category") or "Other",
                    "icon": portal.get("icon") or "box",
                    "order": portal.get("order", 0),
                    "url": _route_url(exposure, portal),
                    "access": _access(service_id, route),
                }
            )
    entries.sort(key=lambda item: (item["order"], item["category"], item["label"], item["id"]))
    return {"schemaVersion": 2, "source": "managed-services-v2", "entries": entries}


def portal_bytes(effective: dict[str, Any]) -> bytes:
    return (json.dumps(compile_portal_projection(effective), indent=2, sort_keys=True) + "\n").encode("utf-8")


__all__ = ["PortalProjectionError", "compile_portal_projection", "portal_bytes"]
