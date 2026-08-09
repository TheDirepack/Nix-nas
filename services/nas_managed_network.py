#!/usr/bin/env python3
"""Managed Services V2 network policy helpers.

This module is deliberately pure except for explicit apply helpers. It gives
V2 services stable, isolated Podman bridge networks and renders the firewalld
policy intent needed to filter those networks. The project does not switch the
host-wide Netavark firewall driver here; strict enforcement remains opt-in until
validated by the VM harness.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError

PROFILE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
SERVICE_ID_RE = PROFILE_ID_RE
PRIVATE_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
POOL = ipaddress.ip_network("10.224.0.0/11")
NETWORK_PREFIX = 28


def _validate_ports(value: Any, *, field: str) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, list) or any(isinstance(port, bool) or not isinstance(port, int) for port in value):
        raise ManagedServiceError(f"{field} must be an array of TCP/UDP port numbers")
    ports = sorted(set(value))
    if any(port < 1 or port > 65535 for port in ports):
        raise ManagedServiceError(f"{field} contains an invalid port")
    return ports


def normalize_network_policy(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ManagedServiceError("network policy must be an object")
    unknown = set(value) - {"outboundDefault", "lanAccess", "allowedEgress", "allowedHostPorts"}
    if unknown:
        raise ManagedServiceError(f"network policy has unsupported keys: {sorted(unknown)}")
    outbound = value.get("outboundDefault", "allow")
    if outbound not in {"allow", "deny"}:
        raise ManagedServiceError("network.outboundDefault must be allow or deny")
    lan_access = value.get("lanAccess", False)
    if not isinstance(lan_access, bool):
        raise ManagedServiceError("network.lanAccess must be boolean")
    allowed: list[dict[str, Any]] = []
    raw_allowed = value.get("allowedEgress", [])
    if not isinstance(raw_allowed, list):
        raise ManagedServiceError("network.allowedEgress must be an array")
    for index, item in enumerate(raw_allowed):
        if not isinstance(item, dict) or set(item) - {"cidr", "ports"}:
            raise ManagedServiceError(f"network.allowedEgress[{index}] is invalid")
        cidr = item.get("cidr")
        if not isinstance(cidr, str):
            raise ManagedServiceError(f"network.allowedEgress[{index}].cidr must be a string")
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ManagedServiceError(f"Invalid CIDR {cidr!r}: {exc}") from exc
        if network.version != 4:
            raise ManagedServiceError("V2 managed Podman network policy currently supports IPv4 CIDRs only")
        allowed.append({"cidr": str(network), "ports": _validate_ports(item.get("ports"), field=f"allowedEgress[{index}].ports")})
    return {
        "outboundDefault": outbound,
        "lanAccess": lan_access,
        "allowedEgress": allowed,
        "allowedHostPorts": _validate_ports(value.get("allowedHostPorts"), field="network.allowedHostPorts"),
    }


def merge_network_policy(profile: Any, override: Any) -> dict[str, Any]:
    base = normalize_network_policy(profile)
    if override is None:
        return base
    if not isinstance(override, dict):
        raise ManagedServiceError("service network override must be an object")
    merged: dict[str, Any] = dict(base)
    for key, val in override.items():
        merged[key] = val
    return normalize_network_policy(merged)


def _network_index(service_id: str) -> int:
    if not SERVICE_ID_RE.fullmatch(service_id):
        raise ManagedServiceError(f"Invalid managed service id {service_id!r}")
    digest = hashlib.blake2s(service_id.encode("utf-8"), digest_size=4, person=b"nas-v2").digest()
    count = 1 << (NETWORK_PREFIX - POOL.prefixlen)
    return int.from_bytes(digest, "big") % count


def service_network(service_id: str) -> dict[str, str]:
    index = _network_index(service_id)
    size = 1 << (32 - NETWORK_PREFIX)
    network = ipaddress.ip_network((int(POOL.network_address) + index * size, NETWORK_PREFIX))
    gateway = ipaddress.ip_address(int(network.network_address) + 1)
    token = hashlib.blake2s(service_id.encode("utf-8"), digest_size=4, person=b"nas-fw").hexdigest()
    return {
        "quadlet": f"nas-v2-{service_id}.network",
        "networkName": f"nas-v2-{service_id}",
        "subnet": str(network),
        "gateway": str(gateway),
        "zone": f"nsv2-{token}",
        "worldPolicy": f"n2w-{token}",
        "hostPolicy": f"n2h-{token}",
    }


def render_network_quadlet(service_id: str) -> str:
    network = service_network(service_id)
    return "\n".join(
        [
            "# Generated by NixOS NAS Managed Services V2; do not edit.",
            "[Network]",
            f"NetworkName={network['networkName']}",
            "Driver=bridge",
            f"Subnet={network['subnet']}",
            f"Gateway={network['gateway']}",
            "Options=isolate=true",
            "",
        ]
    )


def firewalld_plan(service_id: str, policy: Any) -> dict[str, Any]:
    normalized = normalize_network_policy(policy)
    network = service_network(service_id)
    world_rules: list[str] = []
    if not normalized["lanAccess"]:
        for private in PRIVATE_V4:
            world_rules.append(f'rule family="ipv4" destination address="{private}" reject')
    for allowed in normalized["allowedEgress"]:
        cidr = allowed["cidr"]
        ports = allowed["ports"]
        if ports:
            for port in ports:
                world_rules.append(f'rule family="ipv4" destination address="{cidr}" port port="{port}" protocol="tcp" accept')
                world_rules.append(f'rule family="ipv4" destination address="{cidr}" port port="{port}" protocol="udp" accept')
        else:
            world_rules.append(f'rule family="ipv4" destination address="{cidr}" accept')
    host_ports = sorted(set([53, *normalized["allowedHostPorts"]]))
    return {
        "service": service_id,
        "network": network,
        "policy": normalized,
        "worldTarget": "ACCEPT" if normalized["outboundDefault"] == "allow" else "REJECT",
        "worldRules": world_rules,
        "hostPorts": host_ports,
    }


def _run(command: list[str], *, check: bool = True) -> None:
    subprocess.run(command, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def apply_firewalld(service_id: str, policy: Any, *, dry_run: bool = False) -> dict[str, Any]:
    """Apply generated policy objects to firewalld permanent config.

    Object creation is permanent because firewalld only creates custom zones and
    policies there. Reconcile then reloads once to make the generated objects
    effective. This does not change Netavark's global firewall driver.
    """

    plan = firewalld_plan(service_id, policy)
    if dry_run:
        return plan
    n = plan["network"]
    _run(["firewall-cmd", "--permanent", f"--new-zone={n['zone']}"], check=False)
    _run(["firewall-cmd", "--permanent", f"--zone={n['zone']}", f"--add-source={n['subnet']}"], check=False)
    for policy_name in (n["worldPolicy"], n["hostPolicy"]):
        _run(["firewall-cmd", "--permanent", f"--new-policy={policy_name}"], check=False)
    _run(["firewall-cmd", "--permanent", f"--policy={n['worldPolicy']}", f"--add-ingress-zone={n['zone']}"], check=False)
    _run(["firewall-cmd", "--permanent", f"--policy={n['worldPolicy']}", "--add-egress-zone=ANY"], check=False)
    _run(["firewall-cmd", "--permanent", f"--policy={n['worldPolicy']}", f"--set-target={plan['worldTarget']}"], check=True)
    _run(["firewall-cmd", "--permanent", f"--policy={n['worldPolicy']}", "--add-masquerade"], check=False)
    for rule in plan["worldRules"]:
        _run(["firewall-cmd", "--permanent", f"--policy={n['worldPolicy']}", f"--add-rich-rule={rule}"], check=False)
    _run(["firewall-cmd", "--permanent", f"--policy={n['hostPolicy']}", f"--add-ingress-zone={n['zone']}"], check=False)
    _run(["firewall-cmd", "--permanent", f"--policy={n['hostPolicy']}", "--add-egress-zone=HOST"], check=False)
    _run(["firewall-cmd", "--permanent", f"--policy={n['hostPolicy']}", "--set-target=REJECT"], check=True)
    for port in plan["hostPorts"]:
        _run(["firewall-cmd", "--permanent", f"--policy={n['hostPolicy']}", f"--add-port={port}/tcp"], check=False)
        _run(["firewall-cmd", "--permanent", f"--policy={n['hostPolicy']}", f"--add-port={port}/udp"], check=False)
    return plan


def remove_firewalld(service_id: str, *, dry_run: bool = False) -> dict[str, Any]:
    network = service_network(service_id)
    if not dry_run:
        for policy_name in (network["worldPolicy"], network["hostPolicy"]):
            _run(["firewall-cmd", "--permanent", f"--delete-policy={policy_name}"], check=False)
        _run(["firewall-cmd", "--permanent", f"--delete-zone={network['zone']}"], check=False)
    return {"service": service_id, "network": network}
