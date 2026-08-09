#!/usr/bin/env python3
"""Apply one compiled V2 desired-state document to generic subsystems."""

from __future__ import annotations

import os
from typing import Any

import nas_v2_runtime as compiler
from nas_managed_network import apply_firewalld
from nas_v2_listeners import reconcile_listeners


def _apply_runtime(service_id: str, service: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    if service["runtime"]["type"] == "exec":
        from nas_service_runtime_exec import apply_exec

        return apply_exec(service_id, service, dry_run=dry_run)
    return compiler._apply_runtime(service_id, service, dry_run=dry_run)


def apply_document(
    document: dict[str, Any],
    *,
    effective_path=compiler.DEFAULT_EFFECTIVE,
    dry_run: bool = False,
    authentik: bool = True,
) -> dict[str, Any]:
    effective = compiler.compile_effective(document)
    if not dry_run:
        compiler._atomic_json(effective_path, effective)

    result: dict[str, Any] = {
        "effective": str(effective_path),
        "runtimes": {},
        "networks": {},
        "projections": {},
    }
    for service_id in sorted(effective["services"]):
        service = effective["services"][service_id]
        network = service.get("resolvedNetwork")
        if network is not None:
            policy = {key: value for key, value in network.items() if key not in {"identity", "mode"}}
            result["networks"][service_id] = apply_firewalld(service_id, policy, dry_run=dry_run)
        result["runtimes"][service_id] = _apply_runtime(service_id, service, dry_run=dry_run)

    firewall_zone = os.environ.get("NAS_V2_FIREWALL_ZONE", "nas-lan")
    result["listeners"] = reconcile_listeners(document, zone=firewall_zone, dry_run=dry_run)
    if dry_run:
        return result

    from nas_copyparty_projection import atomic_write_config, render_config
    from nas_v2_caddy import write_caddyfile

    atomic_write_config(render_config(effective))
    result["projections"]["copyparty"] = "applied"
    write_caddyfile(effective)
    result["projections"]["caddy"] = "applied"
    result["projections"]["backup"] = "effective-state-published"

    if authentik:
        from nas_authentik_v2_groups import reconcile_groups
        from nas_identity_sync import authentik_token

        result["projections"]["authentik"] = reconcile_groups(authentik_token(), effective)
    return result
