#!/usr/bin/env python3
"""firewalld policy adapter for managed-services."""

from __future__ import annotations

import ipaddress
import os
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError

FIREWALL_ZONE = os.environ.get("NAS_FIREWALL_ZONE", "drop")


def _validate_cidr(cidr: str) -> None:
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ManagedServiceError(f"Invalid CIDR {cidr!r}: {exc}") from exc


def _validate_port(port: Any) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ManagedServiceError(f"Invalid firewall port {port!r}")


def plan_firewall(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    network = service.get("network", {})
    if not isinstance(network, dict):
        raise ManagedServiceError(f"Network policy for {service_id} must be an object")
    endpoints = service.get("endpoints") or {}
    if not isinstance(endpoints, dict):
        raise ManagedServiceError(f"Endpoints for {service_id} must be an object")
    actions: list[dict[str, Any]] = []
    if network.get("lanAccess") is False:
        ports = [
            {"port": ep.get("targetPort"), "protocol": ep.get("transport")}
            for ep in endpoints.values()
            if isinstance(ep, dict) and ep.get("transport") in ("tcp", "udp")
        ]
        actions.append({"type": "deny-lan", "service": service_id, "ports": ports})
    egress_rules = network.get("allowedEgress", [])
    if not isinstance(egress_rules, list):
        raise ManagedServiceError(f"allowedEgress for {service_id} must be an array")
    for egress in egress_rules:
        if not isinstance(egress, dict):
            raise ManagedServiceError(f"allowedEgress for {service_id} must contain objects")
        cidr = egress.get("cidr", "")
        _validate_cidr(cidr)
        ports = egress.get("ports", [])
        if not isinstance(ports, list) or not ports:
            raise ManagedServiceError(f"Egress rule for {service_id} must specify at least one port")
        for port in ports:
            _validate_port(port)
        actions.append(
            {
                "type": "allow-egress",
                "service": service_id,
                "cidr": cidr,
                "ports": ports,
            }
        )
    for eid, ep in endpoints.items():
        if not isinstance(ep, dict):
            raise ManagedServiceError(f"Endpoint {service_id}:{eid} must be an object")
        if ep.get("transport") in ("tcp", "udp"):
            actions.append(
                {
                    "type": "forward",
                    "service": service_id,
                    "endpoint": eid,
                    "port": ep.get("targetPort"),
                    "protocol": ep.get("transport"),
                }
            )
    return {"service": service_id, "actions": actions}


def apply_firewall(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_firewall(service_id, service)
    if dry_run:
        return plan
    for action in plan["actions"]:
        if action["type"] == "deny-lan":
            for endpoint in action["ports"]:
                port = endpoint["port"]
                protocol = endpoint["protocol"]
                rule = (
                    f'rule family="ipv4" source address="192.168.0.0/16" '
                    f'port port="{port}" protocol="{protocol}" reject'
                )
                subprocess.run(
                    ["firewall-cmd", f"--zone={FIREWALL_ZONE}", "--permanent", "--add-rich-rule", rule],
                    check=True,
                )
        elif action["type"] == "allow-egress":
            for port in action["ports"]:
                subprocess.run(
                    [
                        "firewall-cmd",
                        "--permanent",
                        "--direct",
                        "--add-rule",
                        "ipv4",
                        "filter",
                        "OUTPUT",
                        "0",
                        "-d",
                        action["cidr"],
                        "-p",
                        "tcp",
                        "--dport",
                        str(port),
                        "-j",
                        "ACCEPT",
                    ],
                    check=True,
                )
        elif action["type"] == "forward":
            subprocess.run(
                [
                    "firewall-cmd",
                    f"--zone={FIREWALL_ZONE}",
                    "--permanent",
                    f"--add-port={action['port']}/{action['protocol']}",
                ],
                check=True,
            )
        else:
            raise ManagedServiceError(f"Unsupported firewall action {action['type']!r}")
    if plan["actions"]:
        subprocess.run(["firewall-cmd", "--reload"], check=True)
    return plan


def remove_firewall(service_id: str, service: dict[str, Any] | None = None, *, dry_run: bool = False) -> dict[str, Any]:
    if dry_run:
        return {"service": service_id, "removed": [], "dryRun": True}
    if service is None:
        subprocess.run(["firewall-cmd", "--permanent", "--remove-service", service_id], check=False)
        subprocess.run(["firewall-cmd", "--reload"], check=True)
        return {"service": service_id, "removed": [], "legacy": True}

    plan = plan_firewall(service_id, service)
    removed: list[dict[str, Any]] = []
    for action in plan["actions"]:
        if action["type"] == "deny-lan":
            for endpoint in action["ports"]:
                rule = (
                    f'rule family="ipv4" source address="192.168.0.0/16" '
                    f'port port="{endpoint["port"]}" protocol="{endpoint["protocol"]}" reject'
                )
                subprocess.run(
                    ["firewall-cmd", f"--zone={FIREWALL_ZONE}", "--permanent", "--remove-rich-rule", rule],
                    check=False,
                )
        elif action["type"] == "allow-egress":
            for port in action["ports"]:
                subprocess.run(
                    [
                        "firewall-cmd",
                        "--permanent",
                        "--direct",
                        "--remove-rule",
                        "ipv4",
                        "filter",
                        "OUTPUT",
                        "0",
                        "-d",
                        action["cidr"],
                        "-p",
                        "tcp",
                        "--dport",
                        str(port),
                        "-j",
                        "ACCEPT",
                    ],
                    check=False,
                )
        elif action["type"] == "forward":
            subprocess.run(
                [
                    "firewall-cmd",
                    f"--zone={FIREWALL_ZONE}",
                    "--permanent",
                    f"--remove-port={action['port']}/{action['protocol']}",
                ],
                check=False,
            )
        else:
            raise ManagedServiceError(f"Unsupported firewall action {action['type']!r}")
        removed.append(action)
    if removed:
        subprocess.run(["firewall-cmd", "--reload"], check=True)
    return {"service": service_id, "removed": removed}
