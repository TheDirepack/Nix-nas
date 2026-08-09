#!/usr/bin/env python3
"""Managed Services V2 authorization compatibility layer for feature control.

The mature feature controller still owns lifecycle/wake behavior. This wrapper
changes only managed-service endpoint authorization: V2 capability-backed
endpoints are authorized by the corresponding Authentik group. Legacy embedded
user/group policy remains a migration fallback for old service definitions.
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
        import nas_managed_service_v2 as managed_v2

        return managed_v2.effective_registry()
    except Exception:
        return {}


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
    if auth.get("mode", endpoint.get("access", "admin")) == "public":
        return True

    groups = _legacy.split_groups(headers.get("Remote-Groups", ""))
    username = headers.get("Remote-User", "").strip()
    if _legacy.DISABLED_GROUP in groups or not username:
        return False
    if _legacy.ADMIN_GROUP in groups:
        return True

    capability = auth.get("capability")
    if capability is not None:
        try:
            validated = validate_capability_reference(capability)
        except Exception:
            return False
        expected_prefix = f"application.{service_id}."
        if not validated.startswith(expected_prefix):
            return False
        return capability_group_name(validated) in groups

    # Migration fallback only. New V2 endpoint writes should use capability.
    return _ORIGINAL_AUTHORIZE_SERVICE_SCOPE(scope, headers)


def main() -> int:
    _legacy.authorize_service_scope = authorize_service_scope
    return _legacy.main()


if __name__ == "__main__":
    raise SystemExit(main())
