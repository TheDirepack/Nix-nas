#!/usr/bin/env python3
"""Compile Managed Services V2 network intent into firewalld XML.

Managed isolated Podman services receive a stable interface-bound zone plus
outbound policies. V2 routes receive a HOST -> service-zone TCP allowance so
Caddy can reach loopback-published backends. Explicit listeners with
``firewall: true`` receive a trusted-LAN ingress policy. Host-network listeners
use trusted-LAN -> HOST instead, including platform services whose lifecycle is
not V2-managed. A single-port listener may redirect its exposed port to a
different host target port without granting the workload low-port capabilities.
Numeric policy port lists without an explicit protocol are intentionally treated
as transport-neutral and emitted for both TCP and UDP.

The compiler only materializes configuration files. A separate finite reconciler
owns replacement/removal/reload of those files in firewalld's system config.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import pathlib
import subprocess
import tempfile
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from nas_v2_podman_network import bridge_interface_name, network_policy


class FirewalldProjectionError(RuntimeError):
    """Raised when V2 network policy cannot be represented safely."""


def _digest(service_id: str) -> str:
    return hashlib.sha256(service_id.encode("utf-8")).hexdigest()[:12]


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


def _xml_document(lines: list[str]) -> bytes:
    return ('<?xml version="1.0" encoding="utf-8"?>\n' + "\n".join(lines) + "\n").encode("utf-8")


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


def _host_policy_xml(service_id: str, policy: dict[str, Any]) -> bytes:
    zone = zone_name(service_id)
    lines = [
        '<policy target="DROP" priority="-50">',
        f"  <ingress-zone name={quoteattr(zone)}/>",
        '  <egress-zone name="HOST"/>',
        f"  <short>V2 host {escape(service_id)}</short>",
    ]
    for port in sorted(set(policy.get("allowedHostPorts", []))):
        for protocol in ("tcp", "udp"):
            lines.append(f"  <port port={quoteattr(str(port))} protocol={quoteattr(protocol)}/>")
    lines.append("</policy>")
    return _xml_document(lines)


def _lan_policy_xml(service_id: str, policy: dict[str, Any], *, lan_zone: str) -> bytes:
    target = "ACCEPT" if policy.get("lanAccess", False) else "DROP"
    return _xml_document(
        [
            f'<policy target="{target}" priority="-100">',
            f"  <ingress-zone name={quoteattr(zone_name(service_id))}/>",
            f"  <egress-zone name={quoteattr(lan_zone)}/>",
            f"  <short>V2 LAN {escape(service_id)}</short>",
            "</policy>",
        ]
    )


def _egress_rule_xml(rule: dict[str, Any]) -> list[str]:
    raw_cidr = rule.get("cidr")
    if not isinstance(raw_cidr, str):
        raise FirewalldProjectionError("allowedEgress.cidr must be a string")
    try:
        network = ipaddress.ip_network(raw_cidr, strict=False)
    except ValueError as exc:
        raise FirewalldProjectionError(f"invalid allowedEgress CIDR {raw_cidr!r}: {exc}") from exc
    cidr = str(network)
    family = "ipv4" if network.version == 4 else "ipv6"
    ports = rule.get("ports", [])
    if not isinstance(ports, list) or any(not isinstance(port, int) or isinstance(port, bool) for port in ports):
        raise FirewalldProjectionError(f"allowedEgress ports for {raw_cidr!r} are invalid")
    if not ports:
        return [
            f'  <rule family={quoteattr(family)} priority="-10">',
            f"    <destination address={quoteattr(cidr)}/>",
            "    <accept/>",
            "  </rule>",
        ]
    lines: list[str] = []
    for port in sorted(set(ports)):
        for protocol in ("tcp", "udp"):
            lines.extend(
                [
                    f'  <rule family={quoteattr(family)} priority="-10">',
                    f"    <destination address={quoteattr(cidr)}/>",
                    f"    <port port={quoteattr(str(port))} protocol={quoteattr(protocol)}/>",
                    "    <accept/>",
                    "  </rule>",
                ]
            )
    return lines


def _world_policy_xml(service_id: str, policy: dict[str, Any]) -> bytes:
    target = "ACCEPT" if policy.get("outboundDefault", "allow") == "allow" else "DROP"
    lines = [
        f'<policy target="{target}" priority="0">',
        f"  <ingress-zone name={quoteattr(zone_name(service_id))}/>",
        '  <egress-zone name="ANY"/>',
        f"  <short>V2 egress {escape(service_id)}</short>",
    ]
    for rule in policy.get("allowedEgress", []):
        if not isinstance(rule, dict):
            raise FirewalldProjectionError("allowedEgress entries must be objects")
        lines.extend(_egress_rule_xml(rule))
    lines.append("</policy>")
    return _xml_document(lines)


def _listener_ports(service: dict[str, Any]) -> list[tuple[str, str]]:
    listeners = service.get("listeners", {})
    if not isinstance(listeners, dict):
        return []
    entries: set[tuple[str, str]] = set()
    for listener in listeners.values():
        if not isinstance(listener, dict) or listener.get("firewall", True) is not True:
            continue
        protocol = listener.get("protocol")
        exposure = listener.get("exposure")
        if protocol not in {"tcp", "udp"} or not isinstance(exposure, dict):
            raise FirewalldProjectionError("compiled listener is invalid")
        if isinstance(exposure.get("port"), int):
            port = str(exposure["port"])
        elif isinstance(exposure.get("start"), int) and isinstance(exposure.get("end"), int):
            if "targetPort" in listener:
                raise FirewalldProjectionError("listener targetPort is valid only with a single exposed port")
            port = f"{exposure['start']}-{exposure['end']}"
        else:
            raise FirewalldProjectionError("compiled listener exposure is invalid")
        entries.add((port, protocol))
    return sorted(entries)


def _host_listener_rules(service: dict[str, Any]) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    listeners = service.get("listeners", {})
    if not isinstance(listeners, dict):
        return [], []
    ports: set[tuple[str, str]] = set()
    forwards: set[tuple[str, str, str]] = set()
    for listener in listeners.values():
        if not isinstance(listener, dict) or listener.get("firewall", True) is not True:
            continue
        protocol = listener.get("protocol")
        exposure = listener.get("exposure")
        if protocol not in {"tcp", "udp"} or not isinstance(exposure, dict):
            raise FirewalldProjectionError("compiled listener is invalid")
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
        if isinstance(exposure.get("port"), int):
            ports.add((str(exposure["port"]), protocol))
        elif isinstance(exposure.get("start"), int) and isinstance(exposure.get("end"), int):
            ports.add((f"{exposure['start']}-{exposure['end']}", protocol))
        else:
            raise FirewalldProjectionError("compiled listener exposure is invalid")
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


def _allow_policy_xml(
    service_id: str,
    *,
    ingress_zone: str,
    egress_zone: str,
    ports: list[tuple[str, str]],
    label: str,
    forward_ports: list[tuple[str, str, str]] | None = None,
) -> bytes:
    lines = [
        '<policy target="CONTINUE" priority="-50">',
        f"  <ingress-zone name={quoteattr(ingress_zone)}/>",
        f"  <egress-zone name={quoteattr(egress_zone)}/>",
        f"  <short>V2 {escape(label)} {escape(service_id)}</short>",
    ]
    for port, protocol in ports:
        lines.append(f"  <port port={quoteattr(port)} protocol={quoteattr(protocol)}/>")
    for port, protocol, target_port in forward_ports or []:
        lines.append(
            f"  <forward-port port={quoteattr(port)} protocol={quoteattr(protocol)} to-port={quoteattr(target_port)}/>"
        )
    lines.append("</policy>")
    return _xml_document(lines)


def compile_projection(effective: dict[str, Any], *, lan_zone: str) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Return relative firewalld config files and an ownership manifest."""
    if (
        not lan_zone
        or len(lan_zone) > 17
        or not all(character.isalnum() or character in "_-" for character in lan_zone)
    ):
        raise FirewalldProjectionError(f"unsafe firewalld LAN zone name {lan_zone!r}")

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
        runtime = service.get("runtime")
        runtime_type = runtime.get("type") if isinstance(runtime, dict) else None
        listeners = _listener_ports(service)

        generated: dict[str, bytes] = {}
        if mode == "isolated":
            if not service.get("managed", True):
                raise FirewalldProjectionError(
                    f"unmanaged isolated service {service_id!r} has no V2-owned bridge to receive firewalld policy"
                )
            if runtime_type not in {"oci", "quadlet", "compose"}:
                raise FirewalldProjectionError(
                    f"isolated service {service_id!r} requires a runtime with a stable V2 bridge; runtime {runtime_type!r} is not implemented yet"
                )
            if runtime_type == "compose" and (service.get("routes") or service.get("listeners")):
                raise FirewalldProjectionError(
                    f"isolated Compose service {service_id!r} cannot expose routes/listeners while V3 lacks a target container selector"
                )
            service_zone = zone_name(service_id)
            generated.update(
                {
                    f"zones/{service_zone}.xml": _zone_xml(service_id),
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
                    egress_zone=service_zone,
                    ports=routes,
                    label="route",
                )
            if listeners:
                generated[f"policies/{listener_policy_name(service_id)}.xml"] = _allow_policy_xml(
                    service_id,
                    ingress_zone=lan_zone,
                    egress_zone=service_zone,
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
            if listeners:
                raise FirewalldProjectionError(f"network=none service {service_id!r} cannot expose listeners")
        else:
            raise FirewalldProjectionError(f"unsupported network mode {mode!r}")

        for target, content in generated.items():
            if target in files:
                raise FirewalldProjectionError(f"duplicate generated firewalld target {target!r}")
            files[target] = content
            owners.append({"service": service_id, "target": target})

    manifest = {
        "schemaVersion": 1,
        "files": [
            {
                "target": target,
                "sha256": hashlib.sha256(files[target]).hexdigest(),
            }
            for target in sorted(files)
        ],
        "owners": sorted(owners, key=lambda item: (item["service"], item["target"])),
    }
    return files, manifest


def validate_projection(
    files: dict[str, bytes],
    *,
    firewall_offline_cmd: str,
) -> None:
    """Use firewalld's native offline semantic validator before activation."""
    if not files:
        return
    with tempfile.TemporaryDirectory(prefix="nas-v2-firewalld-") as raw_root:
        root = pathlib.Path(raw_root)
        for relative, content in files.items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
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
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            0o640,
        )
    )
    return output


__all__ = [
    "FirewalldProjectionError",
    "compile_projection",
    "host_policy_name",
    "lan_policy_name",
    "listener_policy_name",
    "materialize_projection",
    "route_policy_name",
    "validate_projection",
    "world_policy_name",
    "zone_name",
]
