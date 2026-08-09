#!/usr/bin/env python3
"""Generic authorization and wake gate for Managed Services V2 routes.

The HTTP transport remains the small Unix-socket gate, but authorization and
activation are entirely driven by the compiled V2 document. There are no
application-specific API-key or wake branches here.
"""

from __future__ import annotations

import hmac
import json
import os
import pathlib
from typing import Any

import nas_feature_control as _legacy
from nas_managed_resources import capability_group_name, validate_capability_reference

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


def _credential_value(auth: dict[str, Any], effective: dict[str, Any]) -> str | None:
    credential_id = auth.get("credential")
    credential = effective.get("credentials", {}).get(credential_id)
    if not isinstance(credential, dict):
        return None
    path = credential.get("path")
    if not isinstance(path, str) or not path.startswith("/run/nas-secrets/"):
        return None
    try:
        value = pathlib.Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _secret_authorized(auth: dict[str, Any], effective: dict[str, Any], headers: Any) -> bool:
    expected = _credential_value(auth, effective)
    if expected is None:
        return False
    candidates: list[str] = []
    for source in auth.get("sources", []):
        if source == "bearer":
            authorization = headers.get("Authorization", "")
            if authorization.lower().startswith("bearer "):
                candidates.append(authorization[7:].strip())
        elif isinstance(source, str) and source.startswith("header:"):
            candidates.append(headers.get(source.split(":", 1)[1], "").strip())
    return any(candidate and hmac.compare_digest(candidate, expected) for candidate in candidates)


def _identity_authorized(service_id: str, auth: dict[str, Any], headers: Any) -> bool:
    groups = _legacy.split_groups(headers.get("Remote-Groups", ""))
    username = headers.get("Remote-User", "").strip()
    if _legacy.DISABLED_GROUP in groups or not username:
        return False
    if _legacy.ADMIN_GROUP in groups:
        return True
    capability = auth.get("capability")
    if not isinstance(capability, str):
        return False
    try:
        validated = validate_capability_reference(capability)
    except Exception:
        return False
    if not validated.startswith(f"application.{service_id}."):
        return False
    return capability_group_name(validated) in groups


def _authorized_use(service_id: str, effective: dict[str, Any]) -> bool:
    service = effective.get("services", {}).get(service_id)
    if not isinstance(service, dict) or not service.get("enabled"):
        return False
    workload = service.get("workload") or {}
    kind = workload.get("kind")
    if kind != "daemon":
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
    auth = endpoint.get("auth")
    if not isinstance(auth, dict):
        return False
    mode = auth.get("mode")
    if mode in {"public", "upstream"}:
        authorized = True
    elif mode == "api-key":
        authorized = _secret_authorized(auth, effective, headers)
    elif mode in {"forward-auth", "oidc"}:
        authorized = _identity_authorized(service_id, auth, headers)
    else:
        return False
    return authorized and _authorized_use(service_id, effective)


def main() -> int:
    _legacy.authorize_service_scope = authorize_service_scope
    return _legacy.main()


if __name__ == "__main__":
    raise SystemExit(main())
