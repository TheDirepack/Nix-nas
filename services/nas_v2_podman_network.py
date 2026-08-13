#!/usr/bin/env python3
"""Compile Managed Services V2 network policy into Podman Quadlet networks."""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import uuid
from typing import Any


class PodmanNetworkProjectionError(RuntimeError):
    pass


_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_NM_RUNTIME_DIR = pathlib.PurePosixPath("/run/NetworkManager/system-connections")
_UUID_NAMESPACE = uuid.UUID("c3c4a6a8-fad7-4e36-8d65-1dc57bcae2ab")


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
