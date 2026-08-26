#!/usr/bin/env python3
"""Project V2-owned Podman bridge networks as Quadlet files.

Host VLAN/VRF topology is intentionally absent from this adapter: nmstate owns
that native state before systemd/Quadlet reconciliation begins. This module
only emits the Podman ``.network`` resources needed by managed containers.
"""

from __future__ import annotations

import pathlib
from typing import Any

from nas_v2_network import (
    PodmanNetworkProjectionError,
    _external_egress,
    bridge_interface_name,
    network_policy,
    podman_network_name,
    quadlet_network_reference,
    vlan_binding,
)


def _network_source(service_id: str, owner_unit: str, policy: dict[str, Any], *, network_name: str) -> bytes:
    vlan = vlan_binding(policy)
    lines = [
        "[Unit]",
        f"Description=Managed Services V2 isolated network for {service_id}",
        f"PartOf={owner_unit}",
        "",
        "[Network]",
        f"NetworkName={network_name}",
        f"InterfaceName={bridge_interface_name(service_id)}",
        "Driver=bridge",
        f"Internal={'false' if _external_egress(policy) else 'true'}",
        "Options=isolate=strict",
    ]
    if vlan is not None:
        # The referenced VRF is already reconciled by nmstate in the outer
        # guarded transaction. Do not create a second NetworkManager/systemd
        # owner for the same host topology.
        lines.append(f"Options=vrf={vlan['vrfInterface']}")
    lines.extend(["NetworkDeleteOnStop=true", ""])
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
    source = next(
        (
            pathlib.Path(item["source"])
            for item in links
            if isinstance(item, dict) and item.get("target") == owner and isinstance(item.get("source"), str)
        ),
        None,
    )
    if source is None or source not in files:
        raise PodmanNetworkProjectionError(
            f"isolated Compose service {service_id!r} is missing its generated systemd owner source"
        )
    network_service = reference.removesuffix(".network") + "-network.service"
    files[source] += f"\n[Unit]\nRequires={network_service}\nAfter={network_service}\n".encode()


def augment_projection(
    effective: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    files: dict[pathlib.Path, bytes],
    manifest: dict[str, Any],
    firewalld_enabled: bool = True,
) -> None:
    """Add only Podman/Quadlet network resources to a systemd projection."""
    quadlet_links = manifest.get("quadletLinks")
    if not isinstance(quadlet_links, list):
        raise PodmanNetworkProjectionError("systemd projection manifest is missing quadletLinks")
    known = {item.get("target") for item in quadlet_links if isinstance(item, dict)}
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
        if reference in known:
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
        source = output_dir / "quadlet" / reference
        files[source] = _network_source(
            service_id,
            owner,
            policy,
            network_name=podman_network_name(service_id, service),
        )
        quadlet_links.append({"target": reference, "source": str(source)})
        known.add(reference)
        if runtime_type == "compose":
            _attach_compose_dependency(
                service_id=service_id,
                owner=owner,
                reference=reference,
                files=files,
                manifest=manifest,
            )

    quadlet_links.sort(key=lambda item: item["target"])


__all__ = ["augment_projection"]
