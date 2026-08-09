#!/usr/bin/env python3
"""Reconcile Managed Services V2 capability groups into Authentik.

Authentik remains the authorization authority. This command only ensures that
every V2 object has stable capability-group objects which administrators can
assign through Authentik's native UI. It never creates users, validates users,
manages group membership, or stores a second authorization database.
"""

from __future__ import annotations

import json
import os
import pathlib
import urllib.parse
from collections.abc import Mapping
from typing import Any

from nas_identity_sync import SyncError, authentik_list, authentik_request, authentik_token
from nas_managed_resources import capability_group_name as legacy_group_name
from nas_managed_resources import validate_capability_reference as validate_legacy_capability
from nas_v2_authorization import capability_group_name, desired_capabilities as object_capabilities

EFFECTIVE_PATH = pathlib.Path(
    os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json")
)
MANAGED_ATTRIBUTE = "nixos_nas_v2_capability"


class AuthentikV2GroupError(RuntimeError):
    pass


def desired_capabilities(effective: dict[str, Any]) -> set[str]:
    """Return object-derived V2 capabilities plus explicit legacy route aliases.

    Object capabilities are the canonical model. Explicit application/storage
    capabilities remain projected only so existing assignments keep working
    during migration.
    """

    desired = set(object_capabilities(effective))
    services = effective.get("services", {})
    if not isinstance(services, dict):
        raise AuthentikV2GroupError("effective services must be an object")
    for service_id, service in services.items():
        if not isinstance(service, dict):
            raise AuthentikV2GroupError(f"Service {service_id!r} must be an object")
        for endpoint in (service.get("endpoints") or {}).values():
            if not isinstance(endpoint, dict):
                continue
            auth = endpoint.get("auth") or {}
            explicit = auth.get("capability") if isinstance(auth, dict) else None
            if explicit is None:
                continue
            try:
                desired.add(validate_legacy_capability(explicit))
            except Exception:
                # Canonical v2.* capabilities are already derived above. An
                # endpoint may explicitly name one during migration.
                from nas_v2_authorization import validate_capability

                desired.add(validate_capability(explicit))
    return desired


def _group_name(capability: str) -> str:
    if capability.startswith("v2."):
        return capability_group_name(capability)
    return legacy_group_name(capability)


def reconcile_groups(token: str, effective: dict[str, Any]) -> dict[str, Any]:
    desired = sorted(desired_capabilities(effective))
    existing = {
        str(item.get("name")): item
        for item in authentik_list(token, "core/groups/")
        if isinstance(item.get("name"), str)
    }
    created: list[str] = []
    corrected: list[str] = []

    for capability in desired:
        name = _group_name(capability)
        attributes = {
            MANAGED_ATTRIBUTE: capability,
            "nixos_nas_managed": True,
        }
        current = existing.get(name)
        if current is None:
            authentik_request(
                token,
                "core/groups/",
                method="POST",
                body={"name": name, "is_superuser": False, "attributes": attributes},
            )
            created.append(name)
            continue

        current_attributes = current.get("attributes") if isinstance(current.get("attributes"), Mapping) else {}
        if bool(current.get("is_superuser")) or current_attributes.get(MANAGED_ATTRIBUTE) != capability:
            primary_key = current.get("pk")
            if primary_key is None:
                raise AuthentikV2GroupError(f"Authentik group {name!r} has no primary key")
            encoded_pk = urllib.parse.quote(str(primary_key), safe="")
            authentik_request(
                token,
                f"core/groups/{encoded_pk}/",
                method="PATCH",
                body={"is_superuser": False, "attributes": {**current_attributes, **attributes}},
            )
            corrected.append(name)

    return {
        "desiredCapabilities": desired,
        "createdGroups": created,
        "correctedGroups": corrected,
        "managedGroups": [_group_name(capability) for capability in desired],
    }


def load_effective(path: pathlib.Path = EFFECTIVE_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AuthentikV2GroupError(f"Effective registry is missing: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthentikV2GroupError(f"Unable to read effective registry: {exc}") from exc
    if not isinstance(value, dict):
        raise AuthentikV2GroupError("Effective registry must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="nas-authentik-v2-groups")
    parser.add_argument("--effective", type=pathlib.Path, default=EFFECTIVE_PATH)
    args = parser.parse_args(argv)
    try:
        result = reconcile_groups(authentik_token(), load_effective(args.effective))
    except (AuthentikV2GroupError, SyncError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
