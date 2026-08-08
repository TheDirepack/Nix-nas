#!/usr/bin/env python3
"""firewalld policy adapter for managed-services."""

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


def plan_firewall(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    network = service.get("network", {})
    actions = []
    if network.get("lanAccess") is False:
        actions.append({"type": "deny-lan", "service": service_id})
    for egress in network.get("allowedEgress", []):
        cidr = egress.get("cidr", "")
        _validate_cidr(cidr)
        actions.append(
            {
                "type": "allow-egress",
                "service": service_id,
                "cidr": cidr,
                "ports": egress.get("ports", []),
            }
        )
    for eid, ep in (service.get("endpoints") or {}).items():
        if ep.get("transport") in ("tcp", "udp"):
            actions.append(
                {"type": "forward", "service": service_id, "endpoint": eid, "port": ep.get("targetPort")}
            )
    return {"service": service_id, "actions": actions}


def apply_firewall(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_firewall(service_id, service)
    if dry_run:
        return plan
    for action in plan["actions"]:
        if action["type"] == "deny-lan":
            subprocess.run(
                [
                    "firewall-cmd",
                    "--permanent",
                    "--remove-rich-rule",
                    f'rule family="ipv4" source address="192.168.0.0/16" service name="{service_id}" accept',
                ],
                check=False,
            )
    subprocess.run(["firewall-cmd", "--reload"], check=False)
    return plan


def remove_firewall(service_id: str, *, dry_run: bool = False) -> None:
    if dry_run:
        return
    subprocess.run(["firewall-cmd", "--permanent", "--remove-service", service_id], check=False)
    subprocess.run(["firewall-cmd", "--reload"], check=False)
