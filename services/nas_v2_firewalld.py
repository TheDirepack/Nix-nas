#!/usr/bin/env python3
"""Compile Managed Services V2 network intent into firewalld XML."""

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
    pass


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


def _xml_document(lines: list[str]) -> bytes:
    return ('<?xml version="1.0" encoding="utf-8"?>\n' + "\n".join(lines) + "\n").encode()


def _zone_xml(service_id: str) -> bytes:
    n = escape(service_id)
    return _xml_document(
        [
            "<zone>",
            f"  <short>V2 {n}</short>",
            f"  <description>Managed Services V2 isolated network for {n}</description>",
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
    for port, proto in ports or []:
        lines.append(f"  <port port={quoteattr(port)} protocol={quoteattr(proto)}/>")
    for port, proto, tport in forward_ports or []:
        lines.append(f"  <forward-port port={quoteattr(port)} protocol={quoteattr(proto)} to-port={quoteattr(tport)}/>")
    lines.append("</policy>")
    return _xml_document(lines)


def _host_policy_xml(service_id: str, policy: dict[str, Any]) -> bytes:
    ports = [(str(p), proto) for p in sorted(set(policy.get("allowedHostPorts", []))) for proto in ("tcp", "udp")]
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
    fam = "ipv4" if network.version == 4 else "ipv6"
    ports = rule.get("ports", [])
    if not isinstance(ports, list) or any(not isinstance(p, int) or isinstance(p, bool) for p in ports):
        raise FirewalldProjectionError(f"allowedEgress ports for {raw!r} are invalid")
    if not ports:
        return [
            f'  <rule family={quoteattr(fam)} priority="-10">',
            f"    <destination address={quoteattr(cidr)}/>",
            "    <accept/>",
            "  </rule>",
        ]
    out: list[str] = []
    for p in sorted(set(ports)):
        for proto in ("tcp", "udp"):
            out.extend(
                [
                    f'  <rule family={quoteattr(fam)} priority="-10">',
                    f"    <destination address={quoteattr(cidr)}/>",
                    f"    <port port={quoteattr(str(p))} protocol={quoteattr(proto)}/>",
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
    return _policy_xml(target, "0", zone_name(service_id), "ANY", f"V2 egress {escape(service_id)}", extra=extra)


def _exposure_port(exposure: dict[str, Any]) -> str:
    if isinstance(exposure.get("port"), int):
        return str(exposure["port"])
    if isinstance(exposure.get("start"), int) and isinstance(exposure.get("end"), int):
        return f"{exposure['start']}-{exposure['end']}"
    raise FirewalldProjectionError("compiled listener exposure is invalid")


def _iter_listeners(service: dict[str, Any]):
    listeners = service.get("listeners", {})
    if not isinstance(listeners, dict):
        return []
    out = []
    for lst in listeners.values():
        if not isinstance(lst, dict) or lst.get("firewall", True) is not True:
            continue
        proto = lst.get("protocol")
        exp = lst.get("exposure")
        if proto not in {"tcp", "udp"} or not isinstance(exp, dict):
            raise FirewalldProjectionError("compiled listener is invalid")
        out.append(lst)
    return out


def _listener_ports(service: dict[str, Any]) -> list[tuple[str, str]]:
    entries: set[tuple[str, str]] = set()
    for lst in _iter_listeners(service):
        if "targetPort" in lst:
            raise FirewalldProjectionError("listener targetPort is valid only with a single exposed port")
        entries.add((_exposure_port(lst["exposure"]), lst["protocol"]))
    return sorted(entries)


def _host_listener_rules(service: dict[str, Any]) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    ports: set[tuple[str, str]] = set()
    forwards: set[tuple[str, str, str]] = set()
    for lst in _iter_listeners(service):
        proto = lst["protocol"]
        exp = lst["exposure"]
        tport = lst.get("targetPort")
        if tport is not None:
            eport = exp.get("port")
            if not isinstance(eport, int):
                raise FirewalldProjectionError("listener targetPort is valid only with a single exposed port")
            if not isinstance(tport, int) or isinstance(tport, bool) or not 1 <= tport <= 65535:
                raise FirewalldProjectionError("listener targetPort is invalid")
            if tport != eport:
                forwards.add((str(eport), proto, str(tport)))
                continue
        ports.add((_exposure_port(exp), proto))
    return sorted(ports), sorted(forwards)


def _route_ports(service: dict[str, Any]) -> list[tuple[str, str]]:
    routes = service.get("routes", {})
    if not isinstance(routes, dict):
        return []
    ports: set[tuple[str, str]] = set()
    for rid, route in routes.items():
        tgt = route.get("target") if isinstance(route, dict) else None
        if not isinstance(tgt, dict):
            raise FirewalldProjectionError(f"compiled route {rid!r} is invalid")
        if tgt.get("type") == "unix-http":
            raise FirewalldProjectionError(f"isolated container route {rid!r} cannot use a host Unix-socket target")
        port = tgt.get("port")
        if not isinstance(port, int):
            raise FirewalldProjectionError(f"compiled route {rid!r} is missing a TCP port")
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


def compile_projection(effective: dict[str, Any], *, lan_zone: str) -> tuple[dict[str, bytes], dict[str, Any]]:
    if not lan_zone or len(lan_zone) > 17 or not all(c.isalnum() or c in "_-" for c in lan_zone):
        raise FirewalldProjectionError(f"unsafe firewalld LAN zone name {lan_zone!r}")
    files: dict[str, bytes] = {}
    owners: list[dict[str, str]] = []
    services = effective.get("services")
    if not isinstance(services, dict):
        raise FirewalldProjectionError("compiled effective state is missing services")
    for sid in sorted(services):
        svc = services[sid]
        if not isinstance(svc, dict) or not svc.get("enabled", True):
            continue
        policy = network_policy(effective, svc)
        mode = policy.get("mode", "host")
        rtype = svc.get("runtime", {}).get("type") if isinstance(svc.get("runtime"), dict) else None
        gen: dict[str, bytes] = {}
        if mode == "isolated":
            listeners = _listener_ports(svc)
            if not svc.get("managed", True):
                raise FirewalldProjectionError(
                    f"unmanaged isolated service {sid!r} has no V2-owned bridge to receive firewalld policy"
                )
            if rtype not in {"oci", "quadlet", "compose"}:
                raise FirewalldProjectionError(
                    f"isolated service {sid!r} requires a runtime with a stable V2 bridge; runtime {rtype!r} is not implemented yet"
                )
            z = zone_name(sid)
            gen.update(
                {
                    f"zones/{z}.xml": _zone_xml(sid),
                    f"policies/{host_policy_name(sid)}.xml": _host_policy_xml(sid, policy),
                    f"policies/{lan_policy_name(sid)}.xml": _lan_policy_xml(sid, policy, lan_zone=lan_zone),
                    f"policies/{world_policy_name(sid)}.xml": _world_policy_xml(sid, policy),
                }
            )
            routes = _route_ports(svc)
            if routes:
                gen[f"policies/{route_policy_name(sid)}.xml"] = _allow_policy_xml(
                    sid, ingress_zone="HOST", egress_zone=z, ports=routes, label="route"
                )
            if listeners:
                gen[f"policies/{listener_policy_name(sid)}.xml"] = _allow_policy_xml(
                    sid, ingress_zone=lan_zone, egress_zone=z, ports=listeners, label="listener"
                )
        elif mode == "host":
            hports, fports = _host_listener_rules(svc)
            if hports or fports:
                gen[f"policies/{listener_policy_name(sid)}.xml"] = _allow_policy_xml(
                    sid, ingress_zone=lan_zone, egress_zone="HOST", ports=hports, forward_ports=fports, label="listener"
                )
        elif mode == "none":
            if _listener_ports(svc):
                raise FirewalldProjectionError(f"network=none service {sid!r} cannot expose listeners")
        else:
            raise FirewalldProjectionError(f"unsupported network mode {mode!r}")
        for tgt, content in gen.items():
            if tgt in files:
                raise FirewalldProjectionError(f"duplicate generated firewalld target {tgt!r}")
            files[tgt] = content
            owners.append({"service": sid, "target": tgt})
    manifest = {
        "schemaVersion": 1,
        "files": [{"target": t, "sha256": hashlib.sha256(files[t]).hexdigest()} for t in sorted(files)],
        "owners": sorted(owners, key=lambda i: (i["service"], i["target"])),
    }
    return files, manifest


def validate_projection(files: dict[str, bytes], *, firewall_offline_cmd: str) -> None:
    if not files:
        return
    with tempfile.TemporaryDirectory(prefix="nas-v2-firewalld-") as raw:
        root = pathlib.Path(raw)
        for rel, content in files.items():
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(content)
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
    effective: dict[str, Any], *, output_dir: pathlib.Path, lan_zone: str, firewall_offline_cmd: str
) -> list[tuple[pathlib.Path, bytes, int]]:
    files, manifest = compile_projection(effective, lan_zone=lan_zone)
    validate_projection(files, firewall_offline_cmd=firewall_offline_cmd)
    out: list[tuple[pathlib.Path, bytes, int]] = [(output_dir / rel, c, 0o640) for rel, c in sorted(files.items())]
    out.append((output_dir / "manifest.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o640))
    return out


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
