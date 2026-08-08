#!/usr/bin/env python3
"""Runtime-only Caddy projection for managed services.

System-owned services still use their established Nix-generated Caddy handlers
until those route-specific rewrites are migrated deliberately.  Runtime-owned
containers/Compose/VM endpoints use the dynamic renderer.  This prevents the
v2 built-in normalization fix from creating duplicate handlers today.
"""
from __future__ import annotations

import copy
import pathlib
from typing import Any

import nas_service_caddy as _base


def runtime_projection(effective: dict[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(effective)
    projected["endpoints"] = {
        key: endpoint
        for key, endpoint in effective.get("endpoints", {}).items()
        if endpoint.get("ownership", "runtime") != "system"
    }
    projected["services"] = {
        key: service
        for key, service in effective.get("services", {}).items()
        if service.get("ownership", "runtime") != "system"
    }
    return projected


def generate_caddy_fragment(effective: dict[str, Any]) -> dict[str, Any]:
    return _base.generate_caddy_fragment(runtime_projection(effective))


def generate_caddyfile(effective: dict[str, Any]) -> str:
    return _base.generate_caddyfile(runtime_projection(effective))


def write_caddy_fragment(
    path: pathlib.Path | None = None,
    effective: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if effective is None:
        raise ValueError("effective registry is required for managed runtime Caddy rendering")
    return _base.write_caddy_fragment(path=path, effective=runtime_projection(effective))
