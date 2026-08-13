#!/usr/bin/env python3
"""Compile V2 network policy into Podman networks — delegated to Nix.

The heavy VLAN/VRF/NetworkManager logic is now owned by NixOS
`networking.firewall` and `virtualisation.podman` with `networking.vlans`.
This module keeps the thin validation and stable `nas-v2-*` naming so
existing V2 generators (`quadlet`, `systemd`) still get a deterministic
`Network=` reference without custom 300-line VLAN code.
"""

from __future__ import annotations

import hashlib
import pathlib
from typing import Any


class PodmanNetworkProjectionError(RuntimeError):
    pass


def bridge_interface_name(service_id: str) -> str:
    d = hashlib.sha256(service_id.encode("utf-8")).hexdigest()[:11]
    return f"nv2{d}"


def podman_network_name(service_id: str, service: dict[str, Any]) -> str:
    return f"nas-v2-{service_id}"


def network_policy(effective: dict[str, Any], service: dict[str, Any]) -> dict[str, Any]:
    if "networkProfile" in service:
        profiles = effective.get("networkProfiles", {})
        p = profiles.get(service["networkProfile"]) if isinstance(profiles, dict) else None
        if not isinstance(p, dict):
            raise PodmanNetworkProjectionError("compiled network profile is missing")
        return p
    p = service.get("network")
    if isinstance(p, dict):
        return p
    return {"mode": "host", "outboundDefault": "allow", "lanAccess": False, "allowedHostPorts": [], "allowedEgress": []}


def vlan_binding(policy: dict[str, Any]) -> dict[str, Any] | None:
    vlan_id = policy.get("vlanId")
    parent = policy.get("vlanParent")
    if vlan_id is None and parent is None:
        return None
    if vlan_id is None or parent is None:
        raise PodmanNetworkProjectionError("network vlanId and vlanParent must be specified together")
    if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
        raise PodmanNetworkProjectionError("network vlanId must be 1..4094")
    import re

    if not isinstance(parent, str) or re.fullmatch(r"^[A-Za-z0-9_.:-]{1,64}$", parent) is None:
        raise PodmanNetworkProjectionError("network vlanParent is not a safe interface name")
    return {"id": vlan_id, "parent": parent}


def _needs_isolated_firewalld(service: dict[str, Any], policy: dict[str, Any]) -> bool:
    return (
        policy.get("outboundDefault", "allow") != "deny"
        or bool(policy.get("lanAccess"))
        or bool(policy.get("allowedHostPorts"))
        or bool(policy.get("allowedEgress"))
        or bool(service.get("routes"))
        or bool(service.get("listeners"))
    )


def requires_firewalld(effective: dict[str, Any]) -> bool:
    services = effective.get("services")
    if not isinstance(services, dict):
        raise PodmanNetworkProjectionError("compiled effective state is missing services")
    for svc in services.values():
        if not isinstance(svc, dict) or not svc.get("enabled", True):
            continue
        pol = network_policy(effective, svc)
        if pol.get("mode") == "isolated" and svc.get("managed", True) and _needs_isolated_firewalld(svc, pol):
            return True
        if pol.get("mode") == "host" and svc.get("listeners"):
            return True
    return False


def quadlet_network_reference(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    firewalld_enabled: bool = True,
) -> str:
    pol = network_policy(effective, service)
    mode = pol.get("mode", "host")
    vlan = vlan_binding(pol)
    if mode == "none":
        if service.get("listeners") or service.get("routes"):
            raise PodmanNetworkProjectionError(f"service {service_id!r} network=none cannot expose")
        if vlan is not None:
            raise PodmanNetworkProjectionError(f"service {service_id!r} network=none cannot contain vlan")
        return "none"
    if mode == "host":
        if vlan is not None:
            raise PodmanNetworkProjectionError(f"host-network service {service_id!r} cannot use vlan")
        return "host"
    if mode != "isolated":
        raise PodmanNetworkProjectionError(f"unsupported network mode {mode!r}")
    return f"nas-v2-net-{service_id}.network"


def augment_projection(
    effective: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    files: dict[pathlib.Path, bytes],
    manifest: dict[str, Any],
    firewalld_enabled: bool = True,
    nmcli_bin: str | None = None,
    install_bin: str | None = None,
    rm_bin: str | None = None,
) -> None:
    # Nix now owns VLAN/VRF. Keep a minimal bridge .network so Quadlet still
    # gets a deterministic `Network=` and `PartOf=` without 300 lines of NM code.
    ql = manifest.get("quadletLinks")
    if not isinstance(ql, list):
        raise PodmanNetworkProjectionError("manifest missing quadletLinks")
    services = effective.get("services")
    if not isinstance(services, dict):
        raise PodmanNetworkProjectionError("effective missing services")
    for sid in sorted(services):
        svc = services[sid]
        if not isinstance(svc, dict) or not svc.get("managed", True) or not svc.get("enabled", True):
            continue
        if svc.get("runtime", {}).get("type") not in {"oci", "quadlet", "compose"}:
            continue
        ref = quadlet_network_reference(effective, sid, svc, firewalld_enabled=firewalld_enabled)
        if not ref.endswith(".network"):
            continue
        if any(isinstance(x, dict) and x.get("target") == ref for x in ql):
            continue
        runtime_map = effective.get("derived", {}).get("runtime", {})
        owner = runtime_map.get(sid, {}).get("ownerUnit") if isinstance(runtime_map, dict) else None
        if not isinstance(owner, str):
            owner = f"nas-v2-{sid}.service"
        src = output_dir / "quadlet" / ref
        pol = network_policy(effective, svc)
        external = pol.get("outboundDefault", "allow") == "allow" or bool(pol.get("lanAccess")) or bool(pol.get("allowedEgress"))
        body = "\n".join(
            [
                "[Unit]",
                f"Description=Managed Services V2 isolated network for {sid}",
                f"PartOf={owner}",
                "",
                "[Network]",
                f"NetworkName={podman_network_name(sid, svc)}",
                f"InterfaceName={bridge_interface_name(sid)}",
                "Driver=bridge",
                f"Internal={'false' if external else 'true'}",
                "Options=isolate=strict",
                "NetworkDeleteOnStop=true",
                "",
            ]
        ).encode()
        files[src] = body
        ql.append({"target": ref, "source": str(src)})
    ql.sort(key=lambda x: x["target"])
