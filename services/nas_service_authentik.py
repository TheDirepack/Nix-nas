#!/usr/bin/env python3
"""Authentik application/provider adapter for managed-services."""
from __future__ import annotations
import os
from typing import Any
from nas_managed_service import ManagedServiceError
AUTHENTIK_API = os.environ.get("NAS_AUTHENTIK_API", "http://127.0.0.1:9000/api/v3")
def plan_authentik(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    actions = []
    for eid, ep in (service.get("endpoints") or {}).items():
        auth = ep.get("auth", {})
        mode = auth.get("mode")
        if mode == "oidc":
            actions.append({"type": "oidc-provider", "service": f"{service_id}:{eid}", "auth": auth})
        elif mode == "forward-auth":
            actions.append({"type": "forward-auth", "service": f"{service_id}:{eid}", "auth": auth})
    return {"service": service_id, "actions": actions}
def apply_authentik(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_authentik(service_id, service)
    if dry_run:
        return plan
    return plan
def remove_authentik(service_id: str, *, dry_run: bool = False) -> None:
    pass
