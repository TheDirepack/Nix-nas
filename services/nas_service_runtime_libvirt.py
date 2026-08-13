#!/usr/bin/env python3
"""libvirt/QEMU/KVM runtime adapter for managed-services."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
from typing import Any

from nas_managed_service import ManagedServiceError


def plan_libvirt(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "vm":
        return {"actions": [], "warnings": [f"Service {service_id} is not a VM service"]}
    source = runtime.get("source", "")
    if not source.startswith(f"/var/lib/nas-control/apps/{service_id}/"):
        raise ManagedServiceError(f"VM source for {service_id} must be under /var/lib/nas-control/apps/{service_id}/")
    return {
        "service": service_id,
        "runtime": "vm",
        "actions": [{"type": "libvirt", "domain": service_id, "source": source}],
    }


def apply_libvirt(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_libvirt(service_id, service)
    if dry_run:
        return plan
    for _action in plan["actions"]:
        domain_xml = _render_domain(service_id, service)
        temporary_path: pathlib.Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="nas-libvirt-",
                suffix=".xml",
                delete=False,
            ) as handle:
                handle.write(domain_xml)
                handle.flush()
                temporary_path = pathlib.Path(handle.name)
            subprocess.run(["virsh", "define", str(temporary_path)], check=True)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
        if service.get("enabled"):
            subprocess.run(["virsh", "start", service_id], check=True)
    return plan


def remove_libvirt(service_id: str, *, dry_run: bool = False) -> None:
    if dry_run:
        return
    subprocess.run(["virsh", "destroy", service_id], check=False)
    subprocess.run(["virsh", "undefine", service_id, "--remove-all-storage"], check=True)


def _render_domain(service_id: str, service: dict[str, Any]) -> str:
    resources = service.get("resources", {})
    memory = resources.get("memoryBytes", 2147483648)
    cpus = resources.get("cpus", 2)
    if isinstance(cpus, bool) or not isinstance(cpus, int) or not 1 <= cpus <= 64:
        raise ManagedServiceError(f"VM CPU count for {service_id} must be an integer from 1 to 64")
    return f"""<domain type='kvm'><name>{service_id}</name><metadata><nas:service xmlns:nas="https://nixos-nas.local/service"><id>{service_id}</id><generation>{service.get("generation", 1)}</generation></nas:service></metadata><memory unit='B'>{memory}</memory><vcpu>{cpus}</vcpu><os><type arch='x86_64'>hvm</type></os><devices><emulator>/run/current-system/sw/bin/qemu-kvm</emulator></devices></domain>"""
