#!/usr/bin/env python3
"""firewalld adapter for managed-services.

Raw TCP/UDP exposure is implemented with deterministic forward-port rules.
Network-isolation rules that cannot yet be scoped to a workload are rejected
instead of being silently ignored or accidentally applied host-wide.
"""
from __future__ import annotations

import ipaddress
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError


def _validate_cidr(cidr: str) -> None:
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ManagedServiceError(f"Invalid CIDR {cidr!r}: {exc}") from exc


def _run(args: list[str], *, tolerate_missing: bool = False) -> None:
    result = subprocess.run(["firewall-cmd", *args], capture_output=True, text=True)
    if result.returncode == 0:
        return
    text = f"{result.stdout}\n{result.stderr}".lower()
    if tolerate_missing and any(token in text for token in ("not enabled", "not found", "invalid_rule", "invalid rule")):
        return
    raise ManagedServiceError(f"firewall-cmd {' '.join(args)} failed: {(result.stderr or result.stdout).strip()}")


def plan_firewall(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    network = service.get("network", {}) or {}
    actions: list[dict[str, Any]] = []
    if network.get("lanAccess") is False:
        actions.append({"type": "requires-isolated-network", "service": service_id})
    for egress in network.get("allowedEgress", []):
        cidr = egress.get("cidr", "")
        _validate_cidr(cidr)
        actions.append(
            {
                "type": "requires-egress-policy",
                "service": service_id,
                "cidr": cidr,
                "ports": egress.get("ports", []),
            }
        )
    for endpoint_id, endpoint in (service.get("endpoints") or {}).items():
        transport = endpoint.get("transport")
        exposure = endpoint.get("exposure") or {}
        if transport in ("tcp", "udp") and exposure.get("type") == "port":
            host_port = int(exposure.get("value"))
            target_port = int(endpoint.get("targetPort"))
            actions.append(
                {
                    "type": "forward",
                    "service": service_id,
                    "endpoint": endpoint_id,
                    "protocol": transport,
                    "hostPort": host_port,
                    "targetPort": target_port,
                    "targetAddress": "127.0.0.1",
                }
            )
    return {"service": service_id, "actions": actions}


def _forward_spec(action: dict[str, Any]) -> str:
    return (
        f"port={int(action['hostPort'])}:proto={action['protocol']}:"
        f"toport={int(action['targetPort'])}:toaddr={action['targetAddress']}"
    )


def apply_firewall(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_firewall(service_id, service)
    if dry_run:
        return plan

    unsupported = [
        action for action in plan["actions"] if action["type"] in {"requires-isolated-network", "requires-egress-policy"}
    ]
    if unsupported:
        raise ManagedServiceError(
            "Managed network isolation/egress requires a workload-scoped network zone; "
            "refusing to apply an unsafe host-wide approximation"
        )

    changed = False
    for action in plan["actions"]:
        if action["type"] != "forward":
            continue
        spec = _forward_spec(action)
        query = subprocess.run(
            ["firewall-cmd", "--permanent", "--query-forward-port", spec],
            capture_output=True,
            text=True,
        )
        if query.returncode != 0:
            _run(["--permanent", "--add-forward-port", spec])
            changed = True
    if changed:
        _run(["--reload"])
    return plan


def remove_firewall(service_id: str, service: dict[str, Any] | None = None, *, dry_run: bool = False) -> None:
    if dry_run or service is None:
        return
    plan = plan_firewall(service_id, service)
    changed = False
    for action in plan["actions"]:
        if action["type"] != "forward":
            continue
        spec = _forward_spec(action)
        result = subprocess.run(
            ["firewall-cmd", "--permanent", "--query-forward-port", spec],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            _run(["--permanent", "--remove-forward-port", spec], tolerate_missing=True)
            changed = True
    if changed:
        _run(["--reload"])
