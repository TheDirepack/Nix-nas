#!/usr/bin/env python3
"""Managed Services V2 authorization and wake layer for feature control.

The mature feature controller remains the HTTP transport gate. V2
capability-backed endpoints are authorized by Authentik groups, API-key
endpoints retain their native bearer/X-API-Key contract, and successful access
drives the generic V2 engine. Dependency ordering, devices, storage, network,
and runtime selection are all service-definition data rather than app-specific
wake code.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any

import nas_feature_control as _legacy
from nas_managed_resources import capability_group_name, validate_capability_reference

_ORIGINAL_AUTHORIZE_SERVICE_SCOPE = _legacy.authorize_service_scope


def _load_effective() -> dict[str, Any]:
    cached = _legacy._load_effective_cached()
    data = cached.get("data")
    if isinstance(data, dict):
        return data
    effective_path = pathlib.Path(
        os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json")
    )
    try:
        value = json.loads(effective_path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return value
    except (OSError, json.JSONDecodeError):
        pass
    try:
        import nas_managed_service_engine as managed_v2

        return managed_v2.effective_registry()
    except Exception:
        return {}


def _authorized_use(service_id: str, effective: dict[str, Any]) -> bool:
    """Apply the generic V2 lifecycle after authorization succeeds."""

    service = effective.get("services", {}).get(service_id)
    if not isinstance(service, dict) or not service.get("enabled"):
        return False
    lifecycle = service.get("lifecycle") or {}
    mode = lifecycle.get("mode")
    if mode == "persistent":
        return True
    if mode == "session":
        return False
    if mode != "on-demand":
        return False
    try:
        import nas_managed_service_engine as managed_v2
        import nas_managed_service_v2 as base_v2

        state = base_v2._read_lifecycle_state()
        if service_id in state.get("services", {}):
            managed_v2.touch_service(service_id)
        else:
            managed_v2.start_service(service_id)
        return True
    except Exception as exc:
        print(f"nas-on-demand: managed service {service_id} wake failed: {exc}", file=os.sys.stderr)
        return False


def _has_legacy_assignments(auth: dict[str, Any]) -> bool:
    groups = auth.get("groups")
    users = auth.get("users")
    return (isinstance(groups, list) and bool(groups)) or (isinstance(users, list) and bool(users))


def authorize_service_scope(scope: str, headers: Any) -> bool:
    if not _legacy._is_valid_service_scope(scope):
        return False
    try:
        _, service_id, endpoint_id = scope.split(":", 2)
    except ValueError:
        return False

    effective = _load_effective()
    endpoint = effective.get("endpoints", {}).get(f"{service_id}:{endpoint_id}")
    if not isinstance(endpoint, dict):
        return False
    auth = endpoint.get("auth") or {}
    if not isinstance(auth, dict):
        return False

    mode = auth.get("mode", endpoint.get("access", "admin"))
    authorized = False
    if mode == "public":
        authorized = True
    elif mode == "api-key":
        authorized = _legacy.ai_api_authorized(headers)
    else:
        groups = _legacy.split_groups(headers.get("Remote-Groups", ""))
        username = headers.get("Remote-User", "").strip()
        if _legacy.DISABLED_GROUP in groups or not username:
            return False
        if _legacy.ADMIN_GROUP in groups:
            authorized = True
        else:
            capability = auth.get("capability")
            if capability is not None:
                try:
                    validated = validate_capability_reference(capability)
                except Exception:
                    return False
                expected_prefix = f"application.{service_id}."
                if not validated.startswith(expected_prefix):
                    return False
                authorized = capability_group_name(validated) in groups
                if not authorized and _has_legacy_assignments(auth):
                    authorized = _ORIGINAL_AUTHORIZE_SERVICE_SCOPE(scope, headers)
            else:
                authorized = _ORIGINAL_AUTHORIZE_SERVICE_SCOPE(scope, headers)

    return authorized and _authorized_use(service_id, effective)


def main() -> int:
    _legacy.authorize_service_scope = authorize_service_scope
    return _legacy.main()


if __name__ == "__main__":
    raise SystemExit(main())
