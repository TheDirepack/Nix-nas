#!/usr/bin/env python3
"""Compile Managed Services V2 network policy for native runtimes.

Host VLAN/VRF topology is reconciled by nmstate, Podman bridge networks are
owned by Quadlet, and firewalld activation is handled by
``nas_v2_firewalld_reconcile``. This module contains only the shared network
policy helpers and the validated firewalld projection compiler.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any
from xml.sax.saxutils import escape, quoteattr


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


def _write_line(lines: list[str], key: str, value: Any) -> None:
    if value is not None and value != "":
        lines.append(f"{key}={value}")


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


_REMOTE_ADMIN_PRIORITY = "-300"


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


def _xml_document(lines: list[str]) -> bytes:
    return ('<?xml version="1.0" encoding="utf-8"?>\n' + "\n".join(lines) + "\n").encode()


def _zone_xml(service_id: str) -> bytes:
    name = escape(service_id)
    return _xml_document(
        [
            "<zone>",
            f"  <short>V2 {name}</short>",
            f"  <description>Managed Services V2 isolated network for {name}</description>",
            f"  <interface name={quoteattr(bridge_interface_name(service_id))}/>",
            "</zone>",
        ]
    )


def _policy_xml(
    target: str,
    priority: str,
    ingress: str,
    egress: str,
    short: str,
    ports: list[tuple[str, str]] | None = None,
    forward_ports: list[tuple[str, str, str]] | None = None,
    extra: list[str] | None = None,
) -> bytes:
    lines = [
        f'<policy target="{target}" priority="{priority}">',
        f"  <ingress-zone name={quoteattr(ingress)}/>",
        f"  <egress-zone name={quoteattr(egress)}/>",
        f"  <short>{short}</short>",
    ]
    if extra:
        lines.extend(extra)
    for port, protocol in ports or []:
        lines.append(f"  <port port={quoteattr(port)} protocol={quoteattr(protocol)}/>")
    for port, protocol, target_port in forward_ports or []:
        lines.append(
            f"  <forward-port port={quoteattr(port)} protocol={quoteattr(protocol)} to-port={quoteattr(target_port)}/>"
        )
    lines.append("</policy>")
    return _xml_document(lines)


def _host_policy_xml(service_id: str, policy: dict[str, Any]) -> bytes:
    ports = [
        (str(port), protocol)
        for port in sorted(set(policy.get("allowedHostPorts", [])))
        for protocol in ("tcp", "udp")
    ]
    return _policy_xml("DROP", "-50", zone_name(service_id), "HOST", f"V2 host {escape(service_id)}", ports=ports)


def _lan_policy_xml(service_id: str, policy: dict[str, Any], *, lan_zone: str) -> bytes:
    target = "ACCEPT" if policy.get("lanAccess", False) else "DROP"
    return _policy_xml(target, "-100", zone_name(service_id), lan_zone, f"V2 LAN {escape(service_id)}")


def _egress_rule_xml(rule: dict[str, Any]) -> list[str]:
    raw = rule.get("cidr")
    if not isinstance(raw, str):
        raise FirewalldProjectionError("allowedEgress.cidr must be a string")
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise FirewalldProjectionError(f"invalid allowedEgress CIDR {raw!r}: {exc}") from exc
    cidr = str(network)
    family = "ipv4" if network.version == 4 else "ipv6"
    ports = rule.get("ports", [])
    if not isinstance(ports, list) or any(not isinstance(port, int) or isinstance(port, bool) for port in ports):
        raise FirewalldProjectionError(f"allowedEgress ports for {raw!r} are invalid")
    if not ports:
        return [
            f'  <rule family={quoteattr(family)} priority="-10">',
            f"    <destination address={quoteattr(cidr)}/>",
            "    <accept/>",
            "  </rule>",
        ]
    out: list[str] = []
    for port in sorted(set(ports)):
        for protocol in ("tcp", "udp"):
            out.extend(
                [
                    f'  <rule family={quoteattr(family)} priority="-10">',
                    f"    <destination address={quoteattr(cidr)}/>",
                    f"    <port port={quoteattr(str(port))} protocol={quoteattr(protocol)}/>",
                    "    <accept/>",
                    "  </rule>",
                ]
            )
    return out


def _world_policy_xml(service_id: str, policy: dict[str, Any]) -> bytes:
    target = "ACCEPT" if policy.get("outboundDefault", "allow") == "allow" else "DROP"
    extra: list[str] = []
    for rule in policy.get("allowedEgress", []):
        if not isinstance(rule, dict):
            raise FirewalldProjectionError("allowedEgress entries must be objects")
        extra.extend(_egress_rule_xml(rule))
    return _policy_xml(
        target,
        "0",
        zone_name(service_id),
        "ANY",
        f"V2 egress {escape(service_id)}",
        extra=extra,
    )


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
            raise FirewalldProjectionError(f"isolated container route {route_id!r} cannot use a host Unix-socket target")
        port = target.get("port")
        if not isinstance(port, int):
            raise FirewalldProjectionError(f"compiled route {route_id!r} is missing a TCP port")
        ports.add((str(port), "tcp"))
    return sorted(ports)


def _allow_policy_xml(
    service_id: str,
    *,
    ingress_zone: str,
    egress_zone: str,
    ports: list[tuple[str, str]],
    label: str,
    forward_ports: list[tuple[str, str, str]] | None = None,
) -> bytes:
    return _policy_xml(
        "DROP",
        "-50",
        ingress_zone,
        egress_zone,
        f"V2 {escape(label)} {escape(service_id)}",
        ports=ports,
        forward_ports=forward_ports,
    )


def _remote_admin_policy_xml(lan_zone: str) -> bytes:
    return _policy_xml(
        "ACCEPT",
        _REMOTE_ADMIN_PRIORITY,
        lan_zone,
        "HOST",
        "V2 remote admin",
        ports=_REMOTE_ADMIN_PORTS,
    )


def _validate_lan_zone(lan_zone: str) -> None:
    if not lan_zone or len(lan_zone) > 17 or not all(character.isalnum() or character in "_-" for character in lan_zone):
        raise FirewalldProjectionError(f"unsafe firewalld LAN zone name {lan_zone!r}")


def compile_remote_admin_projection(*, lan_zone: str) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Compile only the remote-admin baseline. Never depends on application policies."""
    _validate_lan_zone(lan_zone)
    target = f"policies/{remote_admin_policy_name()}.xml"
    files = {target: _remote_admin_policy_xml(lan_zone)}
    manifest = {
        "schemaVersion": 1,
        "files": [{"target": target, "sha256": hashlib.sha256(files[target]).hexdigest()}],
        "owners": [{"service": "_remote-admin", "target": target}],
    }
    return files, manifest


def compile_application_projection(
    effective: dict[str, Any], *, lan_zone: str
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Compile only application policies, without the remote-admin baseline."""
    _validate_lan_zone(lan_zone)
    files: dict[str, bytes] = {}
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
        runtime_type = (
            service.get("runtime", {}).get("type") if isinstance(service.get("runtime"), dict) else None
        )
        generated: dict[str, bytes] = {}
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
            generated.update(
                {
                    f"zones/{zone}.xml": _zone_xml(service_id),
                    f"policies/{host_policy_name(service_id)}.xml": _host_policy_xml(service_id, policy),
                    f"policies/{lan_policy_name(service_id)}.xml": _lan_policy_xml(
                        service_id, policy, lan_zone=lan_zone
                    ),
                    f"policies/{world_policy_name(service_id)}.xml": _world_policy_xml(service_id, policy),
                }
            )
            routes = _route_ports(service)
            if routes:
                generated[f"policies/{route_policy_name(service_id)}.xml"] = _allow_policy_xml(
                    service_id,
                    ingress_zone="HOST",
                    egress_zone=zone,
                    ports=routes,
                    label="route",
                )
            if listeners:
                generated[f"policies/{listener_policy_name(service_id)}.xml"] = _allow_policy_xml(
                    service_id,
                    ingress_zone=lan_zone,
                    egress_zone=zone,
                    ports=listeners,
                    label="listener",
                )
        elif mode == "host":
            host_ports, forward_ports = _host_listener_rules(service)
            if host_ports or forward_ports:
                generated[f"policies/{listener_policy_name(service_id)}.xml"] = _allow_policy_xml(
                    service_id,
                    ingress_zone=lan_zone,
                    egress_zone="HOST",
                    ports=host_ports,
                    forward_ports=forward_ports,
                    label="listener",
                )
        elif mode == "none":
            if _listener_ports(service):
                raise FirewalldProjectionError(f"network=none service {service_id!r} cannot expose listeners")
        else:
            raise FirewalldProjectionError(f"unsupported network mode {mode!r}")
        for target, content in generated.items():
            if target in files:
                raise FirewalldProjectionError(f"duplicate generated firewalld target {target!r}")
            files[target] = content
            owners.append({"service": service_id, "target": target})
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "files": [{"target": target, "sha256": hashlib.sha256(files[target]).hexdigest()} for target in sorted(files)],
        "owners": sorted(owners, key=lambda item: (item["service"], item["target"])),
    }
    return files, manifest


def compile_projection(effective: dict[str, Any], *, lan_zone: str) -> tuple[dict[str, bytes], dict[str, Any]]:
    _validate_lan_zone(lan_zone)
    remote_files, remote_manifest = compile_remote_admin_projection(lan_zone=lan_zone)
    app_files, app_manifest = compile_application_projection(effective, lan_zone=lan_zone)
    files = {**remote_files, **app_files}
    combined_files = remote_manifest["files"] + app_manifest["files"]
    combined_owners = remote_manifest["owners"] + app_manifest["owners"]
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "files": sorted(combined_files, key=lambda entry: entry["target"]),
        "owners": sorted(combined_owners, key=lambda item: (item["service"], item["target"])),
    }
    if len({entry["target"] for entry in combined_files}) != len(combined_files):
        raise FirewalldProjectionError(
            "duplicate generated firewalld target across remote-admin and application policies"
        )
    return files, manifest


def validate_projection(files: dict[str, bytes], *, firewall_offline_cmd: str) -> None:
    if not files:
        return
    with tempfile.TemporaryDirectory(prefix="nas-v2-firewalld-") as raw:
        root = pathlib.Path(raw)
        for relative, content in files.items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        firewalld_conf = root / "firewalld.conf"
        if not firewalld_conf.exists():
            try:
                source = pathlib.Path("/etc/firewalld/firewalld.conf")
                if source.is_file():
                    firewalld_conf.write_bytes(source.read_bytes())
                else:
                    firewalld_conf.write_text("[firewalld]\nDefaultZone=public\n", encoding="utf-8")
            except OSError:
                firewalld_conf.write_text("[firewalld]\nDefaultZone=public\n", encoding="utf-8")
        zones_dir = root / "zones"
        zones_dir.mkdir(parents=True, exist_ok=True)
        for native_zone in ("trusted", "public", "drop"):
            source = pathlib.Path(f"/etc/firewalld/zones/{native_zone}.xml")
            destination = zones_dir / f"{native_zone}.xml"
            if not destination.exists() and source.is_file():
                try:
                    destination.write_bytes(source.read_bytes())
                except OSError:
                    pass
        nas_lan = zones_dir / "nas-lan.xml"
        if not nas_lan.exists():
            try:
                nas_lan.write_text(
                    '<?xml version="1.0" encoding="utf-8"?><zone><short>nas-lan</short><description>NAS LAN</description></zone>',
                    encoding="utf-8",
                )
            except OSError:
                pass
        try:
            result = subprocess.run(
                [firewall_offline_cmd, f"--system-config={root}", "--check-config"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewalldProjectionError(f"unable to validate firewalld projection: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise FirewalldProjectionError(f"firewall-offline-cmd rejected V2 policy: {detail}")


def materialize_projection(
    effective: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    lan_zone: str,
    firewall_offline_cmd: str,
) -> list[tuple[pathlib.Path, bytes, int]]:
    files, manifest = compile_projection(effective, lan_zone=lan_zone)
    validate_projection(files, firewall_offline_cmd=firewall_offline_cmd)
    output: list[tuple[pathlib.Path, bytes, int]] = [
        (output_dir / relative, content, 0o640) for relative, content in sorted(files.items())
    ]
    output.append(
        (
            output_dir / "manifest.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
            0o640,
        )
    )
    return output


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
    "validate_projection",
    "vlan_binding",
    "world_policy_name",
    "zone_name",
]
