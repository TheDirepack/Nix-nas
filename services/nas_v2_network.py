#!/usr/bin/env python3
"""Combined V2 network policy: Podman networks, firewalld XML and reconciliation."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from typing import Any
from xml.sax.saxutils import escape, quoteattr


class PodmanNetworkProjectionError(RuntimeError):
    pass


class FirewalldProjectionError(RuntimeError):
    pass


class FirewalldReconcileError(RuntimeError):
    """Raised when V2 firewalld state cannot be reconciled safely."""


_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_NM_RUNTIME_DIR = pathlib.PurePosixPath("/run/NetworkManager/system-connections")
_UUID_NAMESPACE = uuid.UUID("c3c4a6a8-fad7-4e36-8d65-1dc57bcae2ab")
_OWNED_FILE = re.compile(r"^nv2[zhwlri][0-9a-f]{12}\.xml$")


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
    return {"mode": "host", "outboundDefault": "allow", "lanAccess": False, "allowedHostPorts": [], "allowedEgress": []}


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
    ls = service.get("listeners", {})
    return isinstance(ls, dict) and bool(ls)


def _listener_firewall_requested(service: dict[str, Any]) -> bool:
    ls = service.get("listeners", {})
    return isinstance(ls, dict) and any(isinstance(v, dict) and v.get("firewall", True) for v in ls.values())


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
    for svc in services.values():
        if not isinstance(svc, dict) or not svc.get("enabled", True):
            continue
        policy = network_policy(effective, svc)
        mode = policy.get("mode", "host")
        if mode == "isolated" and svc.get("managed", True) and _needs_isolated_firewalld(svc, policy):
            return True
        if mode == "host" and _listener_firewall_requested(svc):
            return True
    return False


def _isolated_supported(
    service_id: str, service: dict[str, Any], policy: dict[str, Any], *, firewalld_enabled: bool
) -> None:
    runtime = service.get("runtime")
    rtype = runtime.get("type") if isinstance(runtime, dict) else None
    vlan_binding(policy)
    if rtype not in {"oci", "quadlet", "compose"}:
        raise PodmanNetworkProjectionError(
            f"isolated service {service_id!r} requires a runtime with a stable V2 bridge; runtime {rtype!r} is not implemented yet"
        )
    if service.get("workload", {}).get("kind") == "session" and rtype != "oci":
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


def quadlet_network_reference(
    effective: dict[str, Any], service_id: str, service: dict[str, Any], *, firewalld_enabled: bool = True
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


def _network_source(service_id: str, owner_unit: str, policy: dict[str, Any], *, network_name: str) -> bytes:
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
            f"Internal={'false' if _external_egress(policy) else 'true'}",
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
    *, service_id: str, owner: str, reference: str, files: dict[pathlib.Path, bytes], manifest: dict[str, Any]
) -> None:
    links = manifest.get("links")
    if not isinstance(links, list):
        raise PodmanNetworkProjectionError("systemd projection manifest is missing links")
    src = next(
        (
            pathlib.Path(i["source"])
            for i in links
            if isinstance(i, dict) and i.get("target") == owner and isinstance(i.get("source"), str)
        ),
        None,
    )
    if src is None or src not in files:
        raise PodmanNetworkProjectionError(
            f"isolated Compose service {service_id!r} is missing its generated systemd owner source"
        )
    svc = reference.removesuffix(".network") + "-network.service"
    files[src] += f"\n[Unit]\nRequires={svc}\nAfter={svc}\n".encode()


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
    if any(isinstance(i, dict) and i.get("target") == vlan["unit"] for i in links):
        return
    if not nmcli_bin or not install_bin or not rm_bin:
        raise PodmanNetworkProjectionError(
            "VLAN-backed application networking requires nmcli, install, and rm projection binaries"
        )
    vrf_src = output_dir / "networkmanager" / f"{vlan['vrfProfile']}.nmconnection"
    vlan_src = output_dir / "networkmanager" / f"{vlan['vlanProfile']}.nmconnection"
    vrf_prof, vlan_prof = _vlan_profile_sources(vlan, nmcli_bin=nmcli_bin)
    files[vrf_src] = vrf_prof
    files[vlan_src] = vlan_prof
    unit_src = output_dir / "units" / vlan["unit"]
    files[unit_src] = _vlan_service_source(
        vlan, vrf_source=vrf_src, vlan_source=vlan_src, nmcli_bin=nmcli_bin, install_bin=install_bin, rm_bin=rm_bin
    )
    links.append({"target": vlan["unit"], "source": str(unit_src)})
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
    qlinks = manifest.get("quadletLinks")
    if not isinstance(qlinks, list):
        raise PodmanNetworkProjectionError("systemd projection manifest is missing quadletLinks")
    known = {i.get("target") for i in qlinks if isinstance(i, dict)}
    services = effective.get("services")
    if not isinstance(services, dict):
        raise PodmanNetworkProjectionError("compiled effective state is missing services")
    for sid in sorted(services):
        svc = services[sid]
        if not isinstance(svc, dict):
            raise PodmanNetworkProjectionError(f"compiled service {sid!r} is invalid")
        rtype = svc.get("runtime", {}).get("type") if isinstance(svc.get("runtime"), dict) else None
        if not svc.get("managed", True) or not svc.get("enabled", True) or rtype not in {"oci", "quadlet", "compose"}:
            continue
        ref = quadlet_network_reference(effective, sid, svc, firewalld_enabled=firewalld_enabled)
        if not ref.endswith(".network"):
            continue
        if ref in known:
            raise PodmanNetworkProjectionError(f"duplicate Quadlet network target {ref!r}")
        if svc.get("workload", {}).get("kind") == "session":
            owner = f"nas-v2-session-{sid}.target"
        else:
            rt = effective.get("derived", {}).get("runtime", {})
            entry = rt.get(sid) if isinstance(rt, dict) else None
            owner = entry.get("ownerUnit") if isinstance(entry, dict) else None
        if not isinstance(owner, str) or not owner.endswith((".service", ".target")):
            raise PodmanNetworkProjectionError(f"isolated container service {sid!r} has an invalid owner unit")
        policy = network_policy(effective, svc)
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
        src = output_dir / "quadlet" / ref
        files[src] = _network_source(sid, owner, policy, network_name=podman_network_name(sid, svc))
        qlinks.append({"target": ref, "source": str(src)})
        known.add(ref)
        if rtype == "compose":
            _attach_compose_dependency(service_id=sid, owner=owner, reference=ref, files=files, manifest=manifest)
    qlinks.sort(key=lambda i: i["target"])
    links = manifest.get("links")
    owned = manifest.get("ownedUnits")
    if isinstance(links, list):
        links.sort(key=lambda i: i["target"])
    if isinstance(owned, list):
        owned.sort()


# ---------------------------------------------------------------------------
# firewalld XML projection
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# firewalld reconciliation
# ---------------------------------------------------------------------------


def _read_manifest(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FirewalldReconcileError(f"unable to read firewalld manifest {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 1 or not isinstance(value.get("files"), list):
        raise FirewalldReconcileError("firewalld projection manifest is invalid")
    return value


def _safe_target(relative: str) -> pathlib.PurePosixPath:
    target = pathlib.PurePosixPath(relative)
    if len(target.parts) != 2 or target.parts[0] not in {"zones", "policies"}:
        raise FirewalldReconcileError(f"unsafe firewalld target {relative!r}")
    if not _OWNED_FILE.fullmatch(target.name):
        raise FirewalldReconcileError(f"firewalld target {relative!r} is outside the V2 ownership namespace")
    return target


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reconcile_run(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewalldReconcileError(f"unable to execute {command[0]}: {exc}") from exc


def _atomic_copy(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temp = pathlib.Path(raw_temp)
    replaced = False
    try:
        with source.open("rb") as reader, os.fdopen(fd, "wb") as writer:
            shutil.copyfileobj(reader, writer)
            writer.flush()
            os.fsync(writer.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, destination)
        replaced = True
    finally:
        if not replaced:
            temp.unlink(missing_ok=True)


def _fsync(directory: pathlib.Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def reconcile(
    *,
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
    system_config: pathlib.Path,
    firewall_cmd: str,
    firewall_offline_cmd: str,
) -> dict[str, Any]:
    manifest = _read_manifest(manifest_path)
    desired: dict[pathlib.PurePosixPath, tuple[pathlib.Path, str]] = {}
    for entry in manifest["files"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("target"), str)
            or not isinstance(entry.get("sha256"), str)
        ):
            raise FirewalldReconcileError("firewalld manifest file entry is invalid")
        relative = _safe_target(entry["target"])
        source = projection_root / str(relative)
        try:
            source.relative_to(projection_root)
        except ValueError as exc:
            raise FirewalldReconcileError(f"projection source escapes root: {source}") from exc
        if not source.is_file() or _sha256(source) != entry["sha256"]:
            raise FirewalldReconcileError(f"projected firewalld file is missing or changed: {source}")
        desired[relative] = (source, entry["sha256"])

    current: set[pathlib.PurePosixPath] = set()
    for directory_name in ("zones", "policies"):
        directory = system_config / directory_name
        directory.mkdir(parents=True, exist_ok=True)
        for path in directory.iterdir():
            if path.is_file() and _OWNED_FILE.fullmatch(path.name):
                current.add(pathlib.PurePosixPath(directory_name) / path.name)

    changed = False
    backups: dict[pathlib.PurePosixPath, bytes | None] = {}
    touched = sorted(current | set(desired), key=str)
    for relative in touched:
        destination = system_config / str(relative)
        backups[relative] = destination.read_bytes() if destination.exists() else None

    try:
        for relative in sorted(current - set(desired), key=str):
            (system_config / str(relative)).unlink()
            changed = True
        for relative, (source, expected_hash) in sorted(desired.items(), key=lambda item: str(item[0])):
            destination = system_config / str(relative)
            try:
                same = destination.is_file() and _sha256(destination) == expected_hash
            except OSError:
                same = False
            if same:
                continue
            if destination.exists() and not _OWNED_FILE.fullmatch(destination.name):
                raise FirewalldReconcileError(f"refusing to overwrite non-V2 firewalld file {destination}")
            _atomic_copy(source, destination)
            changed = True
        if not changed:
            return {"ok": True, "changed": False, "files": sorted(str(item) for item in desired)}

        for directory_name in ("zones", "policies"):
            _fsync(system_config / directory_name)

        checked = _reconcile_run([firewall_offline_cmd, f"--system-config={system_config}", "--check-config"])
        if checked.returncode != 0:
            detail = (checked.stderr or checked.stdout).strip()[:4000]
            raise FirewalldReconcileError(f"combined firewalld configuration is invalid: {detail}")
        reloaded = _reconcile_run([firewall_cmd, "--reload"])
        if reloaded.returncode != 0:
            detail = (reloaded.stderr or reloaded.stdout).strip()[:4000]
            raise FirewalldReconcileError(f"firewalld reload failed: {detail}")
    except Exception as original:
        rollback_error: Exception | None = None
        try:
            for relative, previous in backups.items():
                destination = system_config / str(relative)
                if previous is None:
                    destination.unlink(missing_ok=True)
                    continue
                fd, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.rollback.", dir=destination.parent)
                temp = pathlib.Path(raw_temp)
                replaced = False
                try:
                    with os.fdopen(fd, "wb") as writer:
                        writer.write(previous)
                        writer.flush()
                        os.fsync(writer.fileno())
                    os.chmod(temp, 0o600)
                    os.replace(temp, destination)
                    replaced = True
                finally:
                    if not replaced:
                        temp.unlink(missing_ok=True)
            for directory_name in ("zones", "policies"):
                _fsync(system_config / directory_name)
            rollback = _reconcile_run([firewall_cmd, "--reload"])
            if rollback.returncode != 0:
                raise FirewalldReconcileError((rollback.stderr or rollback.stdout).strip()[:4000])
        except Exception as exc:  # noqa: BLE001
            rollback_error = exc
        if rollback_error is not None:
            raise FirewalldReconcileError(
                f"firewalld activation failed and rollback reload also failed: original={original}; rollback={rollback_error}"
            ) from original
        if isinstance(original, FirewalldReconcileError):
            raise
        raise FirewalldReconcileError(str(original)) from original

    return {"ok": True, "changed": True, "files": sorted(str(item) for item in desired)}


def reconcile_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Activate V2-owned firewalld files with rollback and one native reload."
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--projection-root", required=True)
    parser.add_argument("--system-config", required=True)
    parser.add_argument("--firewall-cmd", default="firewall-cmd")
    parser.add_argument("--firewall-offline-cmd", default="firewall-offline-cmd")
    args = parser.parse_args(argv)
    try:
        result = reconcile(
            manifest_path=pathlib.Path(args.manifest),
            projection_root=pathlib.Path(args.projection_root),
            system_config=pathlib.Path(args.system_config),
            firewall_cmd=args.firewall_cmd,
            firewall_offline_cmd=args.firewall_offline_cmd,
        )
    except FirewalldReconcileError as exc:
        print(f"nas-v2-firewalld-reconcile: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


# Backwards-compat alias: original reconcile module exposed `main`.
main = reconcile_main

__all__ = [
    "PodmanNetworkProjectionError",
    "FirewalldProjectionError",
    "FirewalldReconcileError",
    "bridge_interface_name",
    "podman_network_name",
    "network_policy",
    "vlan_binding",
    "requires_firewalld",
    "quadlet_network_reference",
    "augment_projection",
    "zone_name",
    "host_policy_name",
    "lan_policy_name",
    "world_policy_name",
    "route_policy_name",
    "listener_policy_name",
    "compile_projection",
    "validate_projection",
    "materialize_projection",
    "reconcile",
    "reconcile_main",
    "main",
]
