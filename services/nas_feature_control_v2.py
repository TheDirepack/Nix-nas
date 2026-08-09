#!/usr/bin/env python3
"""Wake-only bridge for Managed Services V2 routes.

Authorization is deliberately not implemented here. Authentik owns capability
assignments and Caddy enforces them before a request reaches this Unix-socket
bridge. This process only verifies that the requested compiled route exists and
starts/touches an already-authorized on-demand daemon.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any

import nas_feature_control as _legacy

EFFECTIVE_PATH = pathlib.Path(
    os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json")
)


def _load_effective() -> dict[str, Any]:
    cached = _legacy._load_effective_cached()
    data = cached.get("data")
    if isinstance(data, dict) and data.get("schemaVersion") == 3:
        return data
    try:
        value = json.loads(EFFECTIVE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _wake(service_id: str, effective: dict[str, Any]) -> bool:
    service = effective.get("services", {}).get(service_id)
    if not isinstance(service, dict) or not service.get("enabled"):
        return False
    workload = service.get("workload") or {}
    if workload.get("kind") != "daemon":
        return False
    activation = workload.get("activation")
    if activation == "persistent":
        return True
    if activation != "on-demand":
        return False
    try:
        import nas_v2_lifecycle as lifecycle

        state = lifecycle._read_state()
        if service_id in state.get("services", {}):
            lifecycle.touch_service(service_id, effective)
        else:
            lifecycle.start_service(service_id, effective)
        return True
    except Exception as exc:
        print(f"nas-on-demand: V2 service {service_id} wake failed: {exc}", file=os.sys.stderr)
        return False


def authorize_service_scope(scope: str, headers: Any) -> bool:
    """Legacy transport callback: trust Caddy authorization, perform wake only."""

    del headers
    if not _legacy._is_valid_service_scope(scope):
        return False
    try:
        _, service_id, endpoint_id = scope.split(":", 2)
    except ValueError:
        return False

    effective = _load_effective()
    endpoint = effective.get("endpoints", {}).get(f"{service_id}:{endpoint_id}")
    if not isinstance(endpoint, dict) or endpoint.get("available") is False:
        return False
    return _wake(service_id, effective)


def main() -> int:
    _legacy.authorize_service_scope = authorize_service_scope
    return _legacy.main()


if __name__ == "__main__":
    raise SystemExit(main())
