#!/usr/bin/env python3
"""Caddy adapter for managed-services — generates validated Caddy JSON fragments from effective registry."""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

import nas_managed_service as msvc

HOSTNAME_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$", re.IGNORECASE)
PORT_RE = re.compile(r"^[0-9]+$")


def _validate_exposure(exposure: dict[str, Any]) -> None:
    typ = exposure.get("type")
    val = exposure.get("value", "")
    if typ == "hostname" or typ == "dns":
        if not HOSTNAME_RE.fullmatch(val):
            raise ValueError(f"Invalid hostname {val!r}")
    elif typ == "port":
        if not PORT_RE.fullmatch(str(val)) or not 1 <= int(val) <= 65535:
            raise ValueError(f"Invalid port {val!r}")
    elif typ == "path":
        if not val.startswith("/"):
            raise ValueError(f"Invalid path {val!r}")
    elif typ not in ("none", None):
        raise ValueError(f"Invalid exposure type {typ!r}")


def generate_caddy_fragment(effective: dict[str, Any] | None = None) -> dict[str, Any]:
    """Generate a deterministic Caddy JSON fragment for managed-service endpoints."""
    if effective is None:
        effective = msvc.effective_registry()
    routes = []
    for key, endpoint in effective.get("endpoints", {}).items():
        # Only handle HTTP endpoints with exposure
        if endpoint.get("transport") not in ("http", "https", None):
            continue
        exposure = endpoint.get("exposure") or {}
        if exposure.get("type") == "none":
            continue
        try:
            _validate_exposure(exposure)
        except ValueError:
            continue
        # Skip built-ins that are already handled by Nix's Caddy config
        if "publicPath" in endpoint:
            continue
        # Generate a deterministic route ID
        route_id = f"nas-managed-{key.replace(':', '-')}"
        host = None
        path = None
        port = None
        if exposure.get("type") == "hostname" or exposure.get("type") == "dns":
            host = exposure.get("value")
        elif exposure.get("type") == "path":
            path = exposure.get("value")
        elif exposure.get("type") == "port":
            port = int(exposure.get("value"))
        # Build a minimal Caddy route (validation will catch conflicts)
        route = {
            "id": route_id,
            "match": [],
            "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": f"127.0.0.1:{endpoint.get('targetPort')}"}]}],
        }
        if host:
            route["match"].append({"host": [host]})
        if path:
            route["match"].append({"path": [path]})
        if port:
            route["match"].append({"port": [port]})
        # Auth: if forward-auth, add forward_auth handler
        auth = endpoint.get("auth") or {}
        if auth.get("mode") == "forward-auth":
            route["handle"].insert(0, {"handler": "forward_auth", "uri": "/auth", "copy_headers": {"Remote-User": "{http.auth.user.id}"}})
        routes.append(route)
    # Sort for determinism and check for conflicts
    routes.sort(key=lambda r: r["id"])
    # Conflict detection: duplicate host/path/port
    seen = set()
    for route in routes:
        key = (tuple(route["match"][0].get("host", [])) if route["match"] and "host" in route["match"][0] else (),
               tuple(route["match"][0].get("path", [])) if route["match"] and "path" in route["match"][0] else (),
               tuple(route["match"][0].get("port", [])) if route["match"] and "port" in route["match"][0] else ())
        if key in seen:
            raise ValueError(f"Duplicate exposure {key} for route {route['id']}")
        seen.add(key)
    return {"routes": routes}


def write_caddy_fragment(path: pathlib.Path | None = None) -> dict[str, Any]:
    """Write the fragment to a file for Caddy to load (or for tests)."""
    fragment = generate_caddy_fragment()
    if path is None:
        path = pathlib.Path("/run/nas-control/caddy-managed.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fragment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return fragment
