#!/usr/bin/env python3
"""Compile Managed Services V2 network policy for native runtimes.

Host VLAN/VRF topology is reconciled by nmstate, Podman bridge networks are
owned by Quadlet, and firewalld activation is handled by
``nas_v2_firewalld_reconcile``. This module contains only the shared network
policy helpers and direct native firewalld object compiler.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
from typing import Any


class PodmanNetworkProjectionError(RuntimeError):
    pass


class FirewalldProjectionError(RuntimeError):
    pass


_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def bridge_interface_name(service_id: str) -> str:
    return f"nv2{hashlib.sha256(service_id.encode()).hexdigest()[:11]}"


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
    vid = policy.get("vlanId")
    parent = policy.get("vlanParent")
    if vid is None and parent is None:
        return None
    if vid is None or parent is None:
        raise PodmanNetworkProjectionError("network vlanId and vlanParent must be specified together")
    if not isinstance(vid, int) or isinstance(vid, bool) or not 1 <= vid <= 4094:
        raise PodmanNetworkProjectionError("network vlanId must be an integer from 1 through 4094")
    if not isinstance(parent, str) or _INTERFACE_RE.fullmatch(parent) is None:
        raise PodmanNetworkProjectionError("network vlanParent is not a safe interface name")
    digest = hashlib.sha256(f"{parent}\0{vid}".encode()).hexdigest()[:10]
    return {
        "id": vid,
        "parent": parent,
        "key": digest,
        "table": 1_000_000_000 + (int(digest, 16) % 3_000_000_000),
        "vrfInterface": f"nv2vrf{digest[:7]}",
        "vlanInterface": f"nv2vl{digest[:8]}",
        "vrfProfile": f"nas-v2-vrf-{digest}",
        "vlanProfile": f"nas-v2-vlan-{digest}",
        "unit": f"nas-v2-vlan-{digest}.service",
    }


def _has_listeners(service: dict[str, Any]) -> bool:
    listeners = service.get("listeners", {})
    return isinstance(listeners, dict) and bool(listeners)


def _listener_firewall_requested(service: dict[str, Any]) -> bool:
    listeners = service.get("listeners", {})
    return isinstance(listeners, dict) and any(
        isinstance(value, dict) and value.get("firewall", True) for value in listeners.values()
    )


def _external_egress(policy: dict[str, Any]) -> bool:
    return (
        policy.get("outboundDefault", "allow") == "allow"
        or bool(policy.get("lanAccess"))
        or bool(policy.get("allowedEgress"))
    )


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
            f"isolated service {service_id!r} requires a runtime with a stable V2 bridge; "
            f"runtime {runtime_type!r} is not implemented yet"
        )
    if service.get("workload", {}).get("kind") == "session" and runtime_type != "oci":
        raise PodmanNetworkProjectionError(
            f"session service {service_id!r} currently requires direct OCI runtime for per-instance execution"
        )
    if service.get("workload", {}).get("kind") == "session" and (service.get("routes") or service.get("listeners")):
        raise PodmanNetworkProjectionError(
            f"session service {service_id!r} cannot expose fixed routes/listeners because concurrent instances "
            "require per-instance endpoints"
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
        if (
            policy.get("outboundDefault", "allow") != "allow"
            or bool(policy.get("lanAccess"))
            or bool(policy.get("allowedHostPorts"))
            or bool(policy.get("allowedEgress"))
            or vlan is not None
        ):
            raise PodmanNetworkProjectionError(
                f"host-network service {service_id!r} restrictions are not safely attributable to one workload"
            )
        return "host"
    if mode != "isolated":
        raise PodmanNetworkProjectionError(f"unsupported network mode {mode!r}")
    _isolated_supported(service_id, service, policy, firewalld_enabled=firewalld_enabled)
    prefix = "nas-v2-snet" if service.get("workload", {}).get("kind") == "session" else "nas-v2-net"
    return f"{prefix}-{service_id}.network"


def _digest(service_id: str) -> str:
    return hashlib.sha256(service_id.encode()).hexdigest()[:12]


def zone_name(service_id: str) -> str:
    return f"nv2z{_digest(service_id)}"


def host_policy_name(service_id: str) -> str:
    return f"nv2h{_digest(service_id)}"


def lan_policy_name(service_id: str) -> str:
    return f"nv2l{_digest(service_id)}"


def world_policy_name(service_id: str) -> str:
    return f"nv2w{_digest(service_id)}"


def route_policy_name(service_id: str) -> str:
    return f"nv2r{_digest(service_id)}"


def listener_policy_name(service_id: str) -> str:
    return f"nv2i{_digest(service_id)}"


def remote_admin_policy_name() -> str:
    return f"nv2m{_digest('remote-admin')}"


# Policy priority order (lower runs first): remote-admin -300 CONTINUE, LAN -100,
# host/route/listener -50, world egress 50. Priority 0 is reserved by firewalld.
_REMOTE_ADMIN_PRIORITY = "-300"
_WORLD_POLICY_PRIORITY = "50"


def _remote_admin_ports() -> list[tuple[str, str]]:  # pragma: no cover - V2 integration
    cockpit_port = os.environ.get("NAS_V2_COCKPIT_PORT", "9092")
    try:
        port_int = int(cockpit_port)
        if not 1 <= port_int <= 65535:
            raise ValueError
        cockpit_port = str(port_int)
    except (ValueError, TypeError):
        cockpit_port = "9092"
    return [("22", "tcp"), (cockpit_port, "tcp"), ("443", "tcp")]


_REMOTE_ADMIN_PORTS: list[tuple[str, str]] = _remote_admin_ports()



def _zone(service_id: str) -> dict[str, Any]:
    return {"kind": "zone", "name": zone_name(service_id), "interface": bridge_interface_name(service_id)}


def _policy(
    name: str, target: str, priority: int, ingress: str, egress: str,
    *, ports: list[tuple[str, str]] | None = None,
    forward_ports: list[tuple[str, str, str]] | None = None,
    rich_rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if target not in {"ACCEPT", "DROP", "CONTINUE"} or priority == 0 or not -32767 <= priority <= 32767:
        raise FirewalldProjectionError("invalid native firewalld policy")
    return {
        "kind": "policy", "name": name, "target": target, "priority": priority,
        "ingress": ingress, "egress": egress,
        "ports": [list(item) for item in (ports or [])],
        "forwardPorts": [list(item) for item in (forward_ports or [])],
        "richRules": rich_rules or [],
    }


def _egress_rules(rule: dict[str, Any]) -> list[dict[str, Any]]:
    raw = rule.get("cidr")
    if not isinstance(raw, str):
        raise FirewalldProjectionError("allowedEgress.cidr must be a string")
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise FirewalldProjectionError(f"invalid allowedEgress CIDR {raw!r}: {exc}") from exc
    ports = rule.get("ports", [])
    if not isinstance(ports, list) or any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in ports
    ):
        raise FirewalldProjectionError(f"allowedEgress ports for {raw!r} are invalid")
    base = {"family": "ipv4" if network.version == 4 else "ipv6", "destination": str(network)}
    if not ports:
        return [base]
    return [
        {**base, "port": str(port), "protocol": protocol}
        for port in sorted(set(ports)) for protocol in ("tcp", "udp")
    ]


def _exposure_port(exposure: dict[str, Any]) -> str:
    if isinstance(exposure.get("port"), int):
        return str(exposure["port"])
    if isinstance(exposure.get("start"), int) and isinstance(exposure.get("end"), int):
        return f"{exposure['start']}-{exposure['end']}"
    raise FirewalldProjectionError("compiled listener exposure is invalid")


def _iter_listeners(service: dict[str, Any]) -> list[dict[str, Any]]:
    listeners = service.get("listeners", {})
    if not isinstance(listeners, dict):
        return []
    out: list[dict[str, Any]] = []
    for listener in listeners.values():
        if not isinstance(listener, dict) or listener.get("firewall", True) is not True:
            continue
        protocol = listener.get("protocol")
        exposure = listener.get("exposure")
        if protocol not in {"tcp", "udp"} or not isinstance(exposure, dict):
            raise FirewalldProjectionError("compiled listener is invalid")
        out.append(listener)
    return out


def _listener_ports(service: dict[str, Any]) -> list[tuple[str, str]]:
    entries: set[tuple[str, str]] = set()
    for listener in _iter_listeners(service):
        if "targetPort" in listener:
            raise FirewalldProjectionError("listener targetPort is valid only with a single exposed port")
        entries.add((_exposure_port(listener["exposure"]), listener["protocol"]))
    return sorted(entries)


def _host_listener_rules(service: dict[str, Any]) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    ports: set[tuple[str, str]] = set()
    forwards: set[tuple[str, str, str]] = set()
    for listener in _iter_listeners(service):
        protocol = listener["protocol"]
        exposure = listener["exposure"]
        target_port = listener.get("targetPort")
        if target_port is not None:
            exposed_port = exposure.get("port")
            if not isinstance(exposed_port, int):
                raise FirewalldProjectionError("listener targetPort is valid only with a single exposed port")
            if not isinstance(target_port, int) or isinstance(target_port, bool) or not 1 <= target_port <= 65535:
                raise FirewalldProjectionError("listener targetPort is invalid")
            if target_port != exposed_port:
                forwards.add((str(exposed_port), protocol, str(target_port)))
                continue
        ports.add((_exposure_port(exposure), protocol))
    return sorted(ports), sorted(forwards)


def _route_ports(service: dict[str, Any]) -> list[tuple[str, str]]:
    routes = service.get("routes", {})
    if not isinstance(routes, dict):
        return []
    ports: set[tuple[str, str]] = set()
    for route_id, route in routes.items():
        target = route.get("target") if isinstance(route, dict) else None
        if not isinstance(target, dict):
            raise FirewalldProjectionError(f"compiled route {route_id!r} is invalid")
        if target.get("type") == "unix-http":
            raise FirewalldProjectionError(
                f"isolated container route {route_id!r} cannot use a host Unix-socket target"
            )
        port = target.get("port")
        if not isinstance(port, int):
            raise FirewalldProjectionError(f"compiled route {route_id!r} is missing a TCP port")
        ports.add((str(port), "tcp"))
    return sorted(ports)



def _allow_policy(
    name: str, *, ingress: str, egress: str,
    ports: list[tuple[str, str]],
    forward_ports: list[tuple[str, str, str]] | None = None,
) -> dict[str, Any]:
    return _policy(name, "DROP", -50, ingress, egress, ports=ports, forward_ports=forward_ports)


def _validate_lan_zone(lan_zone: str) -> None:
    if not lan_zone or len(lan_zone) > 17 or not all(
        character.isalnum() or character in "_-" for character in lan_zone
    ):
        raise FirewalldProjectionError(f"unsafe firewalld LAN zone name {lan_zone!r}")


def compile_remote_admin_projection(*, lan_zone: str) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    _validate_lan_zone(lan_zone)
    name = remote_admin_policy_name()
    objects = {
        f"policies/{name}": _policy(name, "CONTINUE", -300, lan_zone, "HOST", ports=_remote_admin_ports()),
    }
    return objects, {
        "schemaVersion": 2, "objects": list(objects.values()),
        "owners": [{"service": "_remote-admin", "target": f"policies/{name}"}],
    }


def compile_application_projection(
    effective: dict[str, Any], *, lan_zone: str
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Compile application intent directly into firewalld native objects."""
    _validate_lan_zone(lan_zone)
    objects: dict[str, dict[str, Any]] = {}
    owners: list[dict[str, str]] = []
    services = effective.get("services")
    if not isinstance(services, dict):
        raise FirewalldProjectionError("compiled effective state is missing services")
    for service_id in sorted(services):
        service = services[service_id]
        if not isinstance(service, dict) or not service.get("enabled", True):
            continue
        policy = network_policy(effective, service)
        mode = policy.get("mode", "host")
        runtime_type = service.get("runtime", {}).get("type") if isinstance(service.get("runtime"), dict) else None
        generated: dict[str, dict[str, Any]] = {}
        if mode == "isolated":
            listeners = _listener_ports(service)
            if not service.get("managed", True):
                raise FirewalldProjectionError(
                    f"unmanaged isolated service {service_id!r} has no V2-owned bridge to receive firewalld policy"
                )
            if runtime_type not in {"oci", "quadlet", "compose"}:
                raise FirewalldProjectionError(
                    f"isolated service {service_id!r} requires a runtime with a stable V2 bridge; "
                    f"runtime {runtime_type!r} is not implemented yet"
                )
            zone = zone_name(service_id)
            generated[f"zones/{zone}"] = _zone(service_id)
            host_ports = [
                (str(port), protocol) for port in sorted(set(policy.get("allowedHostPorts", [])))
                for protocol in ("tcp", "udp")
            ]
            name = host_policy_name(service_id)
            generated[f"policies/{name}"] = _policy(name, "DROP", -50, zone, "HOST", ports=host_ports)
            name = lan_policy_name(service_id)
            generated[f"policies/{name}"] = _policy(
                name, "ACCEPT" if policy.get("lanAccess", False) else "DROP", -100, zone, lan_zone,
            )
            rich_rules: list[dict[str, Any]] = []
            for entry in policy.get("allowedEgress", []):
                if not isinstance(entry, dict):
                    raise FirewalldProjectionError("allowedEgress entries must be objects")
                rich_rules.extend(_egress_rules(entry))
            name = world_policy_name(service_id)
            generated[f"policies/{name}"] = _policy(
                name, "ACCEPT" if policy.get("outboundDefault", "allow") == "allow" else "DROP",
                50, zone, "ANY", rich_rules=rich_rules,
            )
            routes = _route_ports(service)
            if routes:
                name = route_policy_name(service_id)
                generated[f"policies/{name}"] = _allow_policy(name, ingress="HOST", egress=zone, ports=routes)
            if listeners:
                name = listener_policy_name(service_id)
                generated[f"policies/{name}"] = _allow_policy(
                    name, ingress=lan_zone, egress=zone, ports=listeners,
                )
        elif mode == "host":
            host_ports, forward_ports = _host_listener_rules(service)
            if host_ports or forward_ports:
                name = listener_policy_name(service_id)
                generated[f"policies/{name}"] = _allow_policy(
                    name, ingress=lan_zone, egress="HOST",
                    ports=host_ports, forward_ports=forward_ports,
                )
        elif mode == "none":
            if _listener_ports(service):
                raise FirewalldProjectionError(f"network=none service {service_id!r} cannot expose listeners")
        else:
            raise FirewalldProjectionError(f"unsupported network mode {mode!r}")
        for target, value in generated.items():
            if target in objects:
                raise FirewalldProjectionError(f"duplicate generated firewalld target {target!r}")
            objects[target] = value
            owners.append({"service": service_id, "target": target})
    return objects, {
        "schemaVersion": 2,
        "objects": [objects[target] for target in sorted(objects)],
        "owners": sorted(owners, key=lambda item: (item["service"], item["target"])),
    }


def compile_projection(
    effective: dict[str, Any], *, lan_zone: str
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    remote_objects, remote = compile_remote_admin_projection(lan_zone=lan_zone)
    app_objects, app = compile_application_projection(effective, lan_zone=lan_zone)
    objects = {**remote_objects, **app_objects}
    if len(objects) != len(remote_objects) + len(app_objects):
        raise FirewalldProjectionError("duplicate native firewalld object across remote and application policies")
    return objects, {
        "schemaVersion": 2,
        "objects": [objects[target] for target in sorted(objects)],
        "owners": sorted(remote["owners"] + app["owners"], key=lambda item: (item["service"], item["target"])),
    }


def materialize_projection(
    effective: dict[str, Any], *, output_dir: pathlib.Path, lan_zone: str
) -> list[tuple[pathlib.Path, bytes, int]]:
    _objects, manifest = compile_projection(effective, lan_zone=lan_zone)
    # The native reconciler consumes exactly this projection. No XML files,
    # XML-to-command conversion, or independent firewall rule database.
    return [(output_dir / "manifest.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o640)]


__all__ = [
    "FirewalldProjectionError",
    "PodmanNetworkProjectionError",
    "bridge_interface_name",
    "compile_application_projection",
    "compile_projection",
    "compile_remote_admin_projection",
    "host_policy_name",
    "lan_policy_name",
    "listener_policy_name",
    "materialize_projection",
    "network_policy",
    "podman_network_name",
    "quadlet_network_reference",
    "remote_admin_policy_name",
    "requires_firewalld",
    "route_policy_name",
    "vlan_binding",
    "world_policy_name",
    "zone_name",
]
