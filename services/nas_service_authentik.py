#!/usr/bin/env python3
"""Authentik application/provider adapter for managed-services."""

from __future__ import annotations

import os
import json
import urllib.error
import urllib.request
from typing import Any

from nas_managed_service import ManagedServiceError

AUTHENTIK_API = os.environ.get("NAS_AUTHENTIK_API", "http://127.0.0.1:9000/api/v3")
AUTHENTIK_TOKEN = os.environ.get("NAS_AUTHENTIK_TOKEN", "")


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
    applied: list[dict[str, Any]] = []
    for action in plan["actions"]:
        if action["type"] == "forward-auth":
            # Forward-auth endpoints are served by the appliance-owned outpost;
            # there is no per-service Authentik object to create.
            applied.append({**action, "applied": True, "owner": "nas-outpost"})
            continue
        if action["type"] != "oidc-provider":
            raise ManagedServiceError(f"Unsupported Authentik action {action['type']!r}")
        provider_id = action["auth"].get("providerId")
        if isinstance(provider_id, bool) or not isinstance(provider_id, int) or provider_id < 1:
            raise ManagedServiceError(
                f"OIDC endpoint {action['service']} must reference an existing Authentik providerId"
            )
        if not AUTHENTIK_TOKEN:
            raise ManagedServiceError("NAS_AUTHENTIK_TOKEN is required to validate an OIDC provider")
        request = urllib.request.Request(
            f"{AUTHENTIK_API.rstrip('/')}/providers/oauth2/{provider_id}/",
            headers={"Authorization": f"Bearer {AUTHENTIK_TOKEN}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 200:
                    raise ManagedServiceError(f"Authentik provider {provider_id} returned HTTP {response.status}")
                json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ManagedServiceError(f"Authentik provider {provider_id} is unavailable: HTTP {exc.code}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ManagedServiceError(f"Authentik provider {provider_id} could not be validated") from exc
        applied.append({**action, "applied": True})
    return {**plan, "actions": applied}


def remove_authentik(service_id: str, *, dry_run: bool = False) -> dict[str, Any]:
    # Authentik resources are referenced by stable provider IDs in the service
    # document and are never deleted implicitly with a NAS service.
    return {"service": service_id, "removed": [], "dryRun": dry_run}
