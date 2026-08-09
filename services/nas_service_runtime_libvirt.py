#!/usr/bin/env python3
"""Thin libvirt/QEMU/KVM runtime adapter for managed services.

The user-authored libvirt XML remains the VM definition authority. Managed
Services V2 adds NAS-owned storage and explicit PCI-device policy through a
generated runtime XML projection under /run; the native source is never
rewritten. Persistent storage is never implicitly deleted with the domain.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any

from nas_managed_service import ManagedServiceError

APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
PROJECTION_ROOT = pathlib.Path("/run/nas-control/libvirt")
MAX_DOMAIN_XML_BYTES = 4 * 1024 * 1024
VIRTIOFS_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
PCI_RE = re.compile(r"^([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])$")


def _domain_source(service_id: str, service: dict[str, Any]) -> pathlib.Path:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "vm":
        raise ManagedServiceError(f"Service {service_id} is not a VM service")
    source = runtime.get("source", "")
    if not isinstance(source, str) or not pathlib.PurePosixPath(source).is_absolute():
        raise ManagedServiceError(f"VM source for {service_id} must be under {APP_ROOT / service_id}/")
    app_root = APP_ROOT.resolve()
    root = (app_root / service_id).resolve()
    path = pathlib.Path(source).resolve()
    try:
        root.relative_to(app_root)
        path.relative_to(root)
    except ValueError as exc:
        raise ManagedServiceError(f"VM source for {service_id} must be under {root}/") from exc
    if path.suffix != ".xml":
        raise ManagedServiceError(f"VM source for {service_id} must be a native libvirt .xml definition")
    return path


def _validate_lifecycle(service_id: str, service: dict[str, Any]) -> None:
    lifecycle = service.get("lifecycle") or {}
    if lifecycle.get("mode") == "session" and service.get("enabled"):
        raise ManagedServiceError(
            f"Service {service_id}: session lifecycle is not supported for libvirt domains; "
            "use an explicit disposable clone/overlay workflow"
        )


def _virtiofs_specs(service_id: str, service: dict[str, Any]) -> list[dict[str, str]]:
    specs: list[dict[str, str]] = []
    seen_targets: set[str] = set()
    for mount in service.get("resolvedStorage") or []:
        if not isinstance(mount, dict) or "resource" not in mount:
            continue
        host = mount.get("hostPath")
        guest = mount.get("guestPath")
        mode = mount.get("mode")
        target = mount.get("target")
        if not isinstance(host, str) or not host.startswith("/"):
            raise ManagedServiceError(f"VM service {service_id}: resolved hostPath must be absolute")
        if not isinstance(guest, str) or not guest.startswith("/"):
            raise ManagedServiceError(f"VM service {service_id}: resolved guestPath must be absolute")
        if mode not in {"ro", "rw"}:
            raise ManagedServiceError(f"VM service {service_id}: resolved storage mode must be ro or rw")
        if not isinstance(target, str) or VIRTIOFS_TAG_RE.fullmatch(target) is None:
            raise ManagedServiceError(
                f"VM service {service_id}: every V2 storage attachment requires target=<virtiofs-mount-tag>"
            )
        if target in seen_targets:
            raise ManagedServiceError(f"VM service {service_id}: duplicate virtiofs target {target!r}")
        seen_targets.add(target)
        specs.append(
            {
                "resource": str(mount["resource"]),
                "hostPath": host,
                "guestPath": guest,
                "mode": mode,
                "target": target,
            }
        )
    return specs


def _gpu_hostdev_specs(service_id: str, service: dict[str, Any]) -> list[str]:
    resolved = service.get("resolvedDevices") or []
    if not isinstance(resolved, list):
        raise ManagedServiceError(f"VM service {service_id}: resolvedDevices must be an array")
    addresses: list[str] = []
    for request in resolved:
        if not isinstance(request, dict):
            raise ManagedServiceError(f"VM service {service_id}: resolved device entry must be an object")
        request_name = request.get("request")
        request_addresses = request.get("pciAddresses") or []
        if not request_addresses:
            continue
        if not isinstance(request_name, str) or ":pci:" not in request_name:
            raise ManagedServiceError(
                f"VM service {service_id}: GPU passthrough requires explicit resources.gpus selector required:pci:<address> or optional:pci:<address>"
            )
        for address in request_addresses:
            if not isinstance(address, str) or PCI_RE.fullmatch(address) is None:
                raise ManagedServiceError(f"VM service {service_id}: invalid resolved PCI GPU address {address!r}")
            if address not in addresses:
                addresses.append(address)
    return addresses


def _read_domain_xml(service_id: str, source: pathlib.Path) -> ET.Element:
    try:
        payload = source.read_bytes()
    except OSError as exc:
        raise ManagedServiceError(f"Unable to read VM XML for {service_id}: {exc}") from exc
    if len(payload) > MAX_DOMAIN_XML_BYTES:
        raise ManagedServiceError(f"VM XML for {service_id} exceeds {MAX_DOMAIN_XML_BYTES} bytes")
    lowered = payload.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ManagedServiceError(f"VM XML for {service_id} must not contain DTD or entity declarations")
    try:
        return ET.fromstring(payload)  # nosec B314 -- DTD/entity declarations are rejected above.
    except ET.ParseError as exc:
        raise ManagedServiceError(f"VM XML for {service_id} is invalid: {exc}") from exc


def _ensure_shared_memory(service_id: str, domain: ET.Element) -> None:
    memory = domain.find("memoryBacking")
    if memory is None:
        memory = ET.SubElement(domain, "memoryBacking")
    source = memory.find("source")
    if source is None:
        ET.SubElement(memory, "source", {"type": "memfd"})
    access = memory.find("access")
    if access is None:
        ET.SubElement(memory, "access", {"mode": "shared"})
    elif access.get("mode") != "shared":
        raise ManagedServiceError(f"VM service {service_id}: virtiofs requires memoryBacking access mode='shared'")


def _pci_address_element(parent: ET.Element, address: str) -> None:
    match = PCI_RE.fullmatch(address)
    if match is None:  # pragma: no cover - validated before use
        raise ManagedServiceError(f"Invalid PCI address {address!r}")
    domain, bus, slot, function = match.groups()
    ET.SubElement(
        parent,
        "address",
        {
            "domain": f"0x{domain}",
            "bus": f"0x{bus}",
            "slot": f"0x{slot}",
            "function": f"0x{function}",
        },
    )


def render_domain_projection(service_id: str, service: dict[str, Any]) -> bytes | None:
    specs = _virtiofs_specs(service_id, service)
    gpu_addresses = _gpu_hostdev_specs(service_id, service)
    if not specs and not gpu_addresses:
        return None
    source = _domain_source(service_id, service)
    domain = _read_domain_xml(service_id, source)
    if domain.tag != "domain":
        raise ManagedServiceError(f"VM XML for {service_id} must have a domain root element")
    devices = domain.find("devices")
    if devices is None:
        devices = ET.SubElement(domain, "devices")

    existing_targets = {
        target.get("dir")
        for filesystem in devices.findall("filesystem")
        for target in filesystem.findall("target")
        if target.get("dir")
    }
    existing_hostdevs: set[str] = set()
    for hostdev in devices.findall("hostdev"):
        source_node = hostdev.find("source")
        address_node = source_node.find("address") if source_node is not None else None
        if address_node is None:
            continue
        try:
            value = (
                f"{int(address_node.get('domain', '0'), 0):04x}:"
                f"{int(address_node.get('bus', '0'), 0):02x}:"
                f"{int(address_node.get('slot', '0'), 0):02x}."
                f"{int(address_node.get('function', '0'), 0):x}"
            )
        except ValueError:
            continue
        existing_hostdevs.add(value)

    if specs:
        _ensure_shared_memory(service_id, domain)
    for spec in specs:
        if spec["target"] in existing_targets:
            raise ManagedServiceError(
                f"VM service {service_id}: native XML already defines filesystem target {spec['target']!r}"
            )
        filesystem = ET.SubElement(devices, "filesystem", {"type": "mount", "accessmode": "passthrough"})
        ET.SubElement(filesystem, "driver", {"type": "virtiofs"})
        ET.SubElement(filesystem, "source", {"dir": spec["hostPath"]})
        ET.SubElement(filesystem, "target", {"dir": spec["target"]})
        if spec["mode"] == "ro":
            ET.SubElement(filesystem, "readonly")

    for address in gpu_addresses:
        if address in existing_hostdevs:
            raise ManagedServiceError(f"VM service {service_id}: native XML already defines PCI hostdev {address}")
        hostdev = ET.SubElement(devices, "hostdev", {"mode": "subsystem", "type": "pci", "managed": "yes"})
        source_node = ET.SubElement(hostdev, "source")
        _pci_address_element(source_node, address)

    ET.indent(domain, space="  ")
    return ET.tostring(domain, encoding="utf-8", xml_declaration=True) + b"\n"


def _projection_path(service_id: str) -> pathlib.Path:
    return PROJECTION_ROOT / f"{service_id}.xml"


def _write_domain_projection(service_id: str, service: dict[str, Any]) -> pathlib.Path | None:
    rendered = render_domain_projection(service_id, service)
    path = _projection_path(service_id)
    if rendered is None:
        path.unlink(missing_ok=True)
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def plan_libvirt(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "vm":
        return {"actions": [], "warnings": [f"Service {service_id} is not a VM service"]}
    _validate_lifecycle(service_id, service)
    native_source = _domain_source(service_id, service)
    mounts = _virtiofs_specs(service_id, service)
    gpu_addresses = _gpu_hostdev_specs(service_id, service)
    source = _projection_path(service_id) if mounts or gpu_addresses else native_source
    enabled = bool(service.get("enabled"))
    return {
        "service": service_id,
        "runtime": "libvirt",
        "source": str(source),
        "nativeSource": str(native_source),
        "domain": service_id,
        "enabled": enabled,
        "lifecycle": (service.get("lifecycle") or {}).get("mode"),
        "resolvedStorage": service.get("resolvedStorage", []),
        "resolvedDevices": service.get("resolvedDevices", []),
        "virtiofs": mounts,
        "pciHostDevices": gpu_addresses,
        "actions": [
            {"type": "virsh-define", "domain": service_id, "source": str(source)},
            {"type": "virsh-domain", "domain": service_id, "operation": "start" if enabled else "destroy"},
        ],
    }


def apply_libvirt(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_libvirt(service_id, service)
    if dry_run or not plan["actions"]:
        return plan
    projection = _write_domain_projection(service_id, service)
    plan["source"] = str(projection) if projection is not None else plan["nativeSource"]
    plan["actions"][0]["source"] = plan["source"]
    subprocess.run(["virsh", "define", plan["source"]], check=True)
    if plan["enabled"]:
        state = subprocess.run(
            ["virsh", "domstate", service_id],
            check=False,
            capture_output=True,
            text=True,
        )
        if state.returncode != 0 or state.stdout.strip().lower() not in {"running", "blocked", "paused"}:
            subprocess.run(["virsh", "start", service_id], check=True)
    else:
        subprocess.run(["virsh", "destroy", service_id], check=False)
    return plan


def remove_libvirt(service_id: str, *, dry_run: bool = False) -> None:
    """Remove only the runtime domain definition; persistent storage is explicit."""

    if dry_run:
        return
    subprocess.run(["virsh", "destroy", service_id], check=False)
    result = subprocess.run(["virsh", "undefine", service_id, "--nvram"], check=False)
    if result.returncode != 0:
        subprocess.run(["virsh", "undefine", service_id], check=True)
    _projection_path(service_id).unlink(missing_ok=True)
