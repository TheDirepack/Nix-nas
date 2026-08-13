#!/usr/bin/env python3
"""Compile Managed Services V2 network policy into Podman Quadlet networks.

V2 keeps application containers on Podman's managed bridge so NAT, DNAT and
Caddy-facing published ports continue to work. When a service selects an
802.1Q VLAN, the bridge is attached to a dedicated Linux VRF and NetworkManager
owns a DHCP-backed VLAN interface in that same VRF. This makes the physical
VLAN the routing underlay without switching the container to macvlan/ipvlan,
which would discard Podman's port-forwarding path.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import uuid
from typing import Any


class PodmanNetworkProjectionError(RuntimeError):
    """Raised when V2 network policy cannot be faithfully lowered to Podman."""


_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_NM_RUNTIME_DIR = pathlib.PurePosixPath("/run/NetworkManager/system-connections")
_UUID_NAMESPACE = uuid.UUID("c3c4a6a8-fad7-4e36-8d65-1dc57bcae2ab")


def bridge_interface_name(service_id: str) -> str:
    """Return a stable Linux bridge interface name within the 15-byte interface limit."""
    digest = hashlib.sha256(service_id.encode("utf-8")).hexdigest()[:11]
    return f"nv2{digest}"


def podman_network_name(service_id: str, service: dict[str, Any]) -> str:
    if service.get("workload", {}).get("kind") == "session":
        return f"nas-v2-session-{service_id}"
    return f"nas-v2-{service_id}"


def network_policy(effective: dict[str, Any], service: dict[str, Any]) -> dict[str, Any]:
    if "networkProfile" in service:
        profiles = effective.get("networkProfiles", {})
        policy = profiles.get(service["networkProfile"]) if isinstance(profiles, dict) else None
        if not isinstance(policy, dict):
            raise PodmanNetworkProjectionError("compiled network profile is missing")
        return policy
    policy = service.get("network")
    if isinstance(policy, dict):
        return policy
    return {
        "mode": "host",
        "outboundDefault": "allow",
        "lanAccess": False,
        "allowedHostPorts": [],
        "allowedEgress": [],
    }


def vlan_binding(policy: dict[str, Any]) -> dict[str, Any] | None:
    """Return the deterministic NetworkManager/VRF resource for a VLAN policy."""
    vlan_id = policy.get("vlanId")
    parent = policy.get("vlanParent")
    if vlan_id is None and parent is None:
        return None
    if vlan_id is None or parent is None:
        raise PodmanNetworkProjectionError("network vlanId and vlanParent must be specified together")
    if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
        raise PodmanNetworkProjectionError("network vlanId must be an integer from 1 through 4094")
    if not isinstance(parent, str) or _INTERFACE_RE.fullmatch(parent) is None:
        raise PodmanNetworkProjectionError("network vlanParent is not a safe interface name")

    digest = hashlib.sha256(f"{parent}\0{vlan_id}".encode("utf-8")).hexdigest()[:10]
    vrf_interface = f"nv2vrf{digest[:7]}"
    vlan_interface = f"nv2vl{digest[:8]}"
    table = 1_000_000_000 + (int(digest, 16) % 3_000_000_000)
    return {
        "id": vlan_id,
        "parent": parent,
        "key": digest,
        "table": table,
        "vrfInterface": vrf_interface,
        "vlanInterface": vlan_interface,
        "vrfProfile": f"nas-v2-vrf-{digest}",
        "vlanProfile": f"nas-v2-vlan-{digest}",
        "unit": f"nas-v2-vlan-{digest}.service",
    }


def _listener_firewall_requested(service: dict[str, Any]) -> bool:
    listeners = service.get("listeners", {})
    return isinstance(listeners, dict) and any(
        isinstance(listener, dict) and listener.get("firewall", True) for listener in listeners.values()
    )


def _has_listeners(service: dict[str, Any]) -> bool:
    listeners = service.get("listeners", {})
    return isinstance(listeners, dict) and bool(listeners)


def _external_egress(policy: dict[str, Any]) -> bool:
    return (
        policy.get("outboundDefault", "allow") == "allow"
        or bool(policy.get("lanAccess"))
        or bool(policy.get("allowedEgress"))
    )


def _deny_egress_needs_firewalld(policy: dict[str, Any]) -> bool:
    return policy.get("outboundDefault", "allow") == "deny" and _external_egress(policy)


def _needs_isolated_firewalld(service: dict[str, Any], policy: dict[str, Any]) -> bool:
    return (
        policy.get("outboundDefault", "allow") != "deny"
        or bool(policy.get("lanAccess"))
        or bool(policy.get("allowedHostPorts"))
        or bool(policy.get("allowedEgress"))
        or bool(service.get("routes"))
        or _has_listeners(service)
    )


def requires_firewalld(effective: dict[str, Any]) -> bool:
    """Return whether any enabled V2 service needs firewalld for faithful policy."""
    services = effective.get("services")
    if not isinstance(services, dict):
        raise PodmanNetworkProjectionError("compiled effective state is missing services")
    for service in services.values():
        if not isinstance(service, dict) or not service.get("enabled", True):
            continue
        policy = network_policy(effective, service)
        mode = policy.get("mode", "host")
        if mode == "isolated" and service.get("managed", True) and _needs_isolated_firewalld(service, policy):
            return True
        if mode == "host" and _listener_firewall_requested(service):
            return True
    return False


def _isolated_supported(
    service_id: str,
    service: dict[str, Any],
    policy: dict[str, Any],
    *,
    firewalld_enabled: bool,
) -> None:
    runtime = service.get("runtime")
    runtime_type = runtime.get("type") if isinstance(runtime, dict) else None
    vlan_binding(policy)
    if runtime_type not in {"oci", "quadlet", "compose"}:
        raise PodmanNetworkProjectionError(
            f"isolated service {service_id!r} requires a runtime with a stable V2 bridge; runtime {runtime_type!r} is not implemented yet"
        )
    if service.get("workload", {}).get("kind") == "session" and runtime_type != "oci":
        raise PodmanNetworkProjectionError(
            f"session service {service_id!r} currently requires direct OCI runtime for per-instance execution"
        )
    if service.get("workload", {}).get("kind") == "session" and (service.get("routes") or service.get("listeners")):
        raise PodmanNetworkProjectionError(
            f"session service {service_id!r} cannot expose fixed routes/listeners because concurrent instances require per-instance endpoints"
        )
    if _needs_isolated_firewalld(service, policy) and not firewalld_enabled:
        raise PodmanNetworkProjectionError(
            f"isolated service {service_id!r} requires the V2 firewalld policy projection in the same apply transaction"
        )
    if _deny_egress_needs_firewalld(policy) and not firewalld_enabled:
        raise PodmanNetworkProjectionError(
            f"isolated service {service_id!r} requires the V2 firewalld policy projection in the same apply transaction"
        )


def quadlet_network_reference(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
    *,
    firewalld_enabled: bool = True,
) -> str:
    """Return the V2 Podman network reference for one service."""
    policy = network_policy(effective, service)
    mode = policy.get("mode", "host")
    vlan = vlan_binding(policy)
    if mode == "none":
        if service.get("listeners") or service.get("routes"):
            raise PodmanNetworkProjectionError(f"service {service_id!r} network=none cannot expose listeners/routes")
        if policy.get("allowedHostPorts") or policy.get("allowedEgress") or policy.get("lanAccess") or vlan is not None:
            raise PodmanNetworkProjectionError(f"service {service_id!r} network=none cannot contain network exceptions")
        return "none"
    if mode == "host":
        constrained = (
            policy.get("outboundDefault", "allow") != "allow"
            or bool(policy.get("lanAccess"))
            or bool(policy.get("allowedHostPorts"))
            or bool(policy.get("allowedEgress"))
            or vlan is not None
        )
        if constrained:
            raise PodmanNetworkProjectionError(
                f"host-network service {service_id!r} restrictions are not safely attributable to one workload"
            )
        return "host"
    if mode != "isolated":
        raise PodmanNetworkProjectionError(f"unsupported network mode {mode!r}")
    _isolated_supported(service_id, service, policy, firewalld_enabled=firewalld_enabled)
    prefix = "nas-v2-snet" if service.get("workload", {}).get("kind") == "session" else "nas-v2-net"
    return f"{prefix}-{service_id}.network"


def _network_source(
    service_id: str,
    owner_unit: str,
    policy: dict[str, Any],
    *,
    network_name: str,
) -> bytes:
    external_egress = _external_egress(policy)
    vlan = vlan_binding(policy)
    lines = [
        "[Unit]",
        f"Description=Managed Services V2 isolated network for {service_id}",
        f"PartOf={owner_unit}",
    ]
    if vlan is not None:
        lines.extend([f"Requires={vlan['unit']}", f"After={vlan['unit']}"])
    lines.extend(
        [
            "",
            "[Network]",
            f"NetworkName={network_name}",
            f"InterfaceName={bridge_interface_name(service_id)}",
            "Driver=bridge",
            f"Internal={'false' if external_egress else 'true'}",
            "Options=isolate=strict",
        ]
    )
    if vlan is not None:
        lines.append(f"Options=vrf={vlan['vrfInterface']}")
    lines.extend(["NetworkDeleteOnStop=true", ""])
    return "\n".join(lines).encode()


def _nmcli_offline_profile(nmcli_bin: str, arguments: list[str], *, label: str) -> bytes:
    try:
        result = subprocess.run(
            [nmcli_bin, "--offline", "connection", "add", *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PodmanNetworkProjectionError(f"unable to generate {label} NetworkManager profile: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:4000]
        raise PodmanNetworkProjectionError(f"NetworkManager rejected {label} profile: {detail}")
    if not result.stdout:
        raise PodmanNetworkProjectionError(f"NetworkManager generated an empty {label} profile")
    return result.stdout


def _vlan_profile_sources(vlan: dict[str, Any], *, nmcli_bin: str) -> tuple[bytes, bytes]:
    vrf_uuid = str(uuid.uuid5(_UUID_NAMESPACE, f"vrf:{vlan['key']}"))
    vlan_uuid = str(uuid.uuid5(_UUID_NAMESPACE, f"vlan:{vlan['key']}"))
    vrf = _nmcli_offline_profile(
        nmcli_bin,
        [
            "connection.type",
            "vrf",
            "connection.id",
            vlan["vrfProfile"],
            "connection.uuid",
            vrf_uuid,
            "connection.interface-name",
            vlan["vrfInterface"],
            "connection.autoconnect",
            "yes",
            "vrf.table",
            str(vlan["table"]),
            "ipv4.method",
            "disabled",
            "ipv6.method",
            "disabled",
        ],
        label=f"VLAN {vlan['id']} VRF",
    )
    tagged = _nmcli_offline_profile(
        nmcli_bin,
        [
            "connection.type",
            "vlan",
            "connection.id",
            vlan["vlanProfile"],
            "connection.uuid",
            vlan_uuid,
            "connection.interface-name",
            vlan["vlanInterface"],
            "connection.controller",
            vlan["vrfInterface"],
            "connection.port-type",
            "vrf",
            "connection.autoconnect",
            "yes",
            "vlan.parent",
            vlan["parent"],
            "vlan.id",
            str(vlan["id"]),
            "ipv4.method",
            "auto",
            "ipv4.route-table",
            str(vlan["table"]),
            "ipv4.ignore-auto-dns",
            "yes",
            "ipv6.method",
            "auto",
            "ipv6.route-table",
            str(vlan["table"]),
            "ipv6.ignore-auto-dns",
            "yes",
        ],
        label=f"VLAN {vlan['id']} uplink",
    )
    return vrf, tagged


def _vlan_service_source(
    vlan: dict[str, Any],
    *,
    vrf_source: pathlib.Path,
    vlan_source: pathlib.Path,
    nmcli_bin: str,
    install_bin: str,
    rm_bin: str,
) -> bytes:
    vrf_target = _NM_RUNTIME_DIR / f"{vlan['vrfProfile']}.nmconnection"
    vlan_target = _NM_RUNTIME_DIR / f"{vlan['vlanProfile']}.nmconnection"
    return "\n".join(
        [
            "[Unit]",
            f"Description=Managed Services V2 VLAN {vlan['id']} uplink on {vlan['parent']}",
            "Requires=NetworkManager.service",
            "After=NetworkManager.service network-pre.target",
            "StopWhenUnneeded=yes",
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            f"ExecStartPre={install_bin} -D -m 0600 {vrf_source} {vrf_target}",
            f"ExecStartPre={install_bin} -D -m 0600 {vlan_source} {vlan_target}",
            f"ExecStart={nmcli_bin} connection load {vrf_target} {vlan_target}",
            f"ExecStart={nmcli_bin} --wait 30 connection up id {vlan['vrfProfile']}",
            f"ExecStart={nmcli_bin} --wait 30 connection up id {vlan['vlanProfile']}",
            f"ExecStop=-{nmcli_bin} --wait 10 connection down id {vlan['vlanProfile']}",
            f"ExecStop=-{nmcli_bin} --wait 10 connection down id {vlan['vrfProfile']}",
            f"ExecStop=-{nmcli_bin} connection delete id {vlan['vlanProfile']}",
            f"ExecStop=-{nmcli_bin} connection delete id {vlan['vrfProfile']}",
            f"ExecStopPost=-{rm_bin} -f {vlan_target} {vrf_target}",
            "",
        ]
    ).encode()


def _attach_compose_dependency(
    *,
    service_id: str,
    owner: str,
    reference: str,
    files: dict[pathlib.Path, bytes],
    manifest: dict[str, Any],
) -> None:
    links = manifest.get("links")
    if not isinstance(links, list):
        raise PodmanNetworkProjectionError("systemd projection manifest is missing links")
    owner_source: pathlib.Path | None = None
    for item in links:
        if isinstance(item, dict) and item.get("target") == owner and isinstance(item.get("source"), str):
            owner_source = pathlib.Path(item["source"])
            break
    if owner_source is None or owner_source not in files:
        raise PodmanNetworkProjectionError(
            f"isolated Compose service {service_id!r} is missing its generated systemd owner source"
        )
    network_service = reference.removesuffix(".network") + "-network.service"
    files[owner_source] += (f"\n[Unit]\nRequires={network_service}\nAfter={network_service}\n").encode()


def _ensure_vlan_resource(
    vlan: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    files: dict[pathlib.Path, bytes],
    manifest: dict[str, Any],
    nmcli_bin: str | None,
    install_bin: str | None,
    rm_bin: str | None,
) -> None:
    links = manifest.get("links")
    owned = manifest.get("ownedUnits")
    if not isinstance(links, list) or not isinstance(owned, list):
        raise PodmanNetworkProjectionError("systemd projection manifest is missing V2 ownership metadata")
    if any(isinstance(item, dict) and item.get("target") == vlan["unit"] for item in links):
        return
    if not nmcli_bin or not install_bin or not rm_bin:
        raise PodmanNetworkProjectionError(
            "VLAN-backed application networking requires nmcli, install, and rm projection binaries"
        )

    vrf_source = output_dir / "networkmanager" / f"{vlan['vrfProfile']}.nmconnection"
    vlan_source = output_dir / "networkmanager" / f"{vlan['vlanProfile']}.nmconnection"
    vrf_profile, vlan_profile = _vlan_profile_sources(vlan, nmcli_bin=nmcli_bin)
    files[vrf_source] = vrf_profile
    files[vlan_source] = vlan_profile

    unit_source = output_dir / "units" / vlan["unit"]
    files[unit_source] = _vlan_service_source(
        vlan,
        vrf_source=vrf_source,
        vlan_source=vlan_source,
        nmcli_bin=nmcli_bin,
        install_bin=install_bin,
        rm_bin=rm_bin,
    )
    links.append({"target": vlan["unit"], "source": str(unit_source)})
    if vlan["unit"] not in owned:
        owned.append(vlan["unit"])


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
    """Add V2-owned Podman networks and shared 802.1Q uplink resources."""
    quadlet_links = manifest.get("quadletLinks")
    if not isinstance(quadlet_links, list):
        raise PodmanNetworkProjectionError("systemd projection manifest is missing quadletLinks")
    known_targets = {item.get("target") for item in quadlet_links if isinstance(item, dict)}

    services = effective.get("services")
    if not isinstance(services, dict):
        raise PodmanNetworkProjectionError("compiled effective state is missing services")
    for service_id in sorted(services):
        service = services[service_id]
        if not isinstance(service, dict):
            raise PodmanNetworkProjectionError(f"compiled service {service_id!r} is invalid")
        runtime = service.get("runtime")
        runtime_type = runtime.get("type") if isinstance(runtime, dict) else None
        if (
            not service.get("managed", True)
            or not service.get("enabled", True)
            or runtime_type not in {"oci", "quadlet", "compose"}
        ):
            continue
        reference = quadlet_network_reference(
            effective,
            service_id,
            service,
            firewalld_enabled=firewalld_enabled,
        )
        if not reference.endswith(".network"):
            continue
        if reference in known_targets:
            raise PodmanNetworkProjectionError(f"duplicate Quadlet network target {reference!r}")
        if service.get("workload", {}).get("kind") == "session":
            owner = f"nas-v2-session-{service_id}.target"
        else:
            runtime_map = effective.get("derived", {}).get("runtime", {})
            runtime_entry = runtime_map.get(service_id) if isinstance(runtime_map, dict) else None
            owner = runtime_entry.get("ownerUnit") if isinstance(runtime_entry, dict) else None
        if not isinstance(owner, str) or not owner.endswith((".service", ".target")):
            raise PodmanNetworkProjectionError(f"isolated container service {service_id!r} has an invalid owner unit")

        policy = network_policy(effective, service)
        vlan = vlan_binding(policy)
        if vlan is not None:
            _ensure_vlan_resource(
                vlan,
                output_dir=output_dir,
                files=files,
                manifest=manifest,
                nmcli_bin=nmcli_bin,
                install_bin=install_bin,
                rm_bin=rm_bin,
            )

        source = output_dir / "quadlet" / reference
        files[source] = _network_source(
            service_id,
            owner,
            policy,
            network_name=podman_network_name(service_id, service),
        )
        quadlet_links.append({"target": reference, "source": str(source)})
        known_targets.add(reference)
        if runtime_type == "compose":
            _attach_compose_dependency(
                service_id=service_id,
                owner=owner,
                reference=reference,
                files=files,
                manifest=manifest,
            )

    quadlet_links.sort(key=lambda item: item["target"])
    links = manifest.get("links")
    owned = manifest.get("ownedUnits")
    if isinstance(links, list):
        links.sort(key=lambda item: item["target"])
    if isinstance(owned, list):
        owned.sort()


__all__ = [
    "PodmanNetworkProjectionError",
    "augment_projection",
    "bridge_interface_name",
    "network_policy",
    "podman_network_name",
    "quadlet_network_reference",
    "requires_firewalld",
    "vlan_binding",
]
