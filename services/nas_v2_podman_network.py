#!/usr/bin/env python3
"""Compile Managed Services V2 network policy into Podman Quadlet networks."""

from __future__ import annotations

import hashlib
import pathlib
from typing import Any


class PodmanNetworkProjectionError(RuntimeError):
    """Raised when V2 network policy cannot be faithfully lowered to Podman."""


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


def _vlan_id(policy: dict[str, Any]) -> int | None:
    vlan_id = policy.get("vlanId")
    if vlan_id is None:
        return None
    if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
        raise PodmanNetworkProjectionError("network vlanId must be an integer from 1 through 4094")
    return vlan_id


def _listener_firewall_requested(service: dict[str, Any]) -> bool:
    listeners = service.get("listeners", {})
    return isinstance(listeners, dict) and any(
        isinstance(listener, dict) and listener.get("firewall", True) for listener in listeners.values()
    )


def _needs_isolated_firewalld(service: dict[str, Any], policy: dict[str, Any]) -> bool:
    return (
        policy.get("outboundDefault", "allow") != "deny"
        or bool(policy.get("lanAccess"))
        or bool(policy.get("allowedHostPorts"))
        or bool(policy.get("allowedEgress"))
        or bool(service.get("routes"))
        or _listener_firewall_requested(service)
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
    _vlan_id(policy)
    if runtime_type not in {"oci", "quadlet", "compose"}:
        raise PodmanNetworkProjectionError(
            f"isolated service {service_id!r} requires a runtime with a stable V2 bridge; runtime {runtime_type!r} is not implemented yet"
        )
    if service.get("workload", {}).get("kind") == "session" and runtime_type != "oci":
        raise PodmanNetworkProjectionError(
            f"session service {service_id!r} currently requires direct OCI runtime for per-instance execution"
        )
    if runtime_type == "compose" and (service.get("routes") or service.get("listeners")):
        raise PodmanNetworkProjectionError(
            f"isolated Compose service {service_id!r} cannot expose routes/listeners because V3 has no target container selector for those fields"
        )
    if service.get("workload", {}).get("kind") == "session" and (service.get("routes") or service.get("listeners")):
        raise PodmanNetworkProjectionError(
            f"session service {service_id!r} cannot expose fixed routes/listeners because concurrent instances require per-instance endpoints"
        )
    if _needs_isolated_firewalld(service, policy) and not firewalld_enabled:
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
    vlan_id = _vlan_id(policy)
    if mode == "none":
        if service.get("listeners") or service.get("routes"):
            raise PodmanNetworkProjectionError(f"service {service_id!r} network=none cannot expose listeners/routes")
        if policy.get("allowedHostPorts") or policy.get("allowedEgress") or policy.get("lanAccess") or vlan_id is not None:
            raise PodmanNetworkProjectionError(f"service {service_id!r} network=none cannot contain network exceptions")
        return "none"
    if mode == "host":
        constrained = (
            policy.get("outboundDefault", "allow") != "allow"
            or bool(policy.get("lanAccess"))
            or bool(policy.get("allowedHostPorts"))
            or bool(policy.get("allowedEgress"))
            or vlan_id is not None
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
    external_egress = (
        policy.get("outboundDefault", "allow") == "allow"
        or bool(policy.get("lanAccess"))
        or bool(policy.get("allowedEgress"))
    )
    lines = [
        "[Unit]",
        f"Description=Managed Services V2 isolated network for {service_id}",
        f"PartOf={owner_unit}",
        "",
        "[Network]",
        f"NetworkName={network_name}",
        f"InterfaceName={bridge_interface_name(service_id)}",
        "Driver=bridge",
        f"Internal={'false' if external_egress else 'true'}",
        "Options=isolate=strict",
    ]
    vlan_id = _vlan_id(policy)
    if vlan_id is not None:
        lines.append(f"Options=vlan={vlan_id}")
    lines.extend(
        [
            "NetworkDeleteOnStop=true",
            "",
        ]
    )
    return "\n".join(lines).encode()


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


def augment_projection(
    effective: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    files: dict[pathlib.Path, bytes],
    manifest: dict[str, Any],
    firewalld_enabled: bool = True,
) -> None:
    """Add V2-owned Podman .network Quadlets for enabled managed isolated container services."""
    links = manifest.get("quadletLinks")
    if not isinstance(links, list):
        raise PodmanNetworkProjectionError("systemd projection manifest is missing quadletLinks")
    known_targets = {item.get("target") for item in links if isinstance(item, dict)}

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
        source = output_dir / "quadlet" / reference
        files[source] = _network_source(
            service_id,
            owner,
            network_policy(effective, service),
            network_name=podman_network_name(service_id, service),
        )
        links.append({"target": reference, "source": str(source)})
        known_targets.add(reference)
        if runtime_type == "compose":
            _attach_compose_dependency(
                service_id=service_id,
                owner=owner,
                reference=reference,
                files=files,
                manifest=manifest,
            )

    links.sort(key=lambda item: item["target"])


__all__ = [
    "PodmanNetworkProjectionError",
    "augment_projection",
    "bridge_interface_name",
    "network_policy",
    "podman_network_name",
    "quadlet_network_reference",
    "requires_firewalld",
]
