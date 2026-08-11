#!/usr/bin/env python3
"""Thin libvirt adapter for Managed Services V2 transient VM workloads.

The native domain XML remains authority. V2 securely parses it, derives a
temporary domain XML with only generic virtiofs and explicit PCI host-device
additions, and starts it as a transient libvirt domain. Removing V2 state never
deletes VM storage or leaves a V2-created persistent domain definition behind.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from typing import Any

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException


class LibvirtProjectionError(RuntimeError):
    """Raised when VM policy cannot be represented safely by libvirt."""


APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
_PCI = re.compile(
    r"^pci:(?P<domain>[0-9A-Fa-f]{4}):(?P<bus>[0-9A-Fa-f]{2}):(?P<slot>[0-9A-Fa-f]{2})\.(?P<function>[0-7])$"
)


def _source(service_id: str, service: dict[str, Any]) -> tuple[pathlib.Path, ET.Element]:
    candidate = pathlib.Path(service["runtime"]["source"])
    if candidate.suffix.lower() != ".xml":
        raise LibvirtProjectionError(f"VM service {service_id!r} source must be an XML file")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to((APP_ROOT / service_id).resolve(strict=False))
    except (OSError, ValueError) as exc:
        raise LibvirtProjectionError(
            f"VM service {service_id!r} source must exist beneath its managed app root"
        ) from exc
    if not resolved.is_file():
        raise LibvirtProjectionError(f"VM service {service_id!r} source must name a file")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise LibvirtProjectionError(f"unable to read VM domain XML {resolved}: {exc}") from exc
    try:
        # Only the parsing step touches administrator-controlled XML. Tree
        # construction/rendering below uses stdlib ElementTree on the already
        # parsed in-memory tree.
        root = DefusedET.fromstring(raw)
    except DefusedXmlException as exc:
        raise LibvirtProjectionError(f"unsafe VM domain XML: {exc}") from exc
    except ET.ParseError as exc:
        raise LibvirtProjectionError(f"invalid VM domain XML: {exc}") from exc
    if root.tag != "domain":
        raise LibvirtProjectionError("VM domain XML root must be <domain>")
    return resolved, root


def _domain_name(root: ET.Element) -> str:
    names = root.findall("name")
    if len(names) != 1 or not names[0].text or not names[0].text.strip():
        raise LibvirtProjectionError("VM domain XML must contain exactly one non-empty <name>")
    name = names[0].text.strip()
    if any(character in name for character in ("\x00", "\r", "\n")):
        raise LibvirtProjectionError("VM domain name contains a forbidden control character")
    return name


def _devices(root: ET.Element) -> ET.Element:
    devices = root.findall("devices")
    if len(devices) > 1:
        raise LibvirtProjectionError("VM domain XML may contain only one <devices> element")
    if devices:
        return devices[0]
    return ET.SubElement(root, "devices")


def _ensure_virtiofs_memory(root: ET.Element) -> None:
    memory_backing = root.find("memoryBacking")
    if memory_backing is None:
        memory_backing = ET.Element("memoryBacking")
        ET.SubElement(memory_backing, "source", {"type": "memfd"})
        ET.SubElement(memory_backing, "access", {"mode": "shared"})
        devices = root.find("devices")
        if devices is None:
            root.append(memory_backing)
        else:
            root.insert(list(root).index(devices), memory_backing)
        return
    source = memory_backing.find("source")
    access = memory_backing.find("access")
    if source is None or source.get("type") != "memfd" or access is None or access.get("mode") != "shared":
        raise LibvirtProjectionError(
            "VM virtiofs attachments require compatible memoryBacking source=memfd and access=shared"
        )


def _existing_virtiofs_tags(devices: ET.Element) -> set[str]:
    tags: set[str] = set()
    for filesystem in devices.findall("filesystem"):
        target = filesystem.find("target")
        if target is not None and target.get("dir"):
            tags.add(target.get("dir", ""))
    return tags


def _add_storage(effective: dict[str, Any], service: dict[str, Any], root: ET.Element) -> None:
    if not service["storage"]:
        return
    _ensure_virtiofs_memory(root)
    devices = _devices(root)
    used_tags = _existing_virtiofs_tags(devices)
    resources = effective.get("storageResources", {})
    for attachment in service["storage"]:
        resource = resources.get(attachment["resource"])
        if not isinstance(resource, dict) or not isinstance(resource.get("path"), str):
            raise LibvirtProjectionError(f"compiled storage resource {attachment['resource']!r} is missing")
        mount_tag = attachment.get("mountTag")
        if not isinstance(mount_tag, str) or not mount_tag:
            raise LibvirtProjectionError("VM storage attachments require mountTag")
        if mount_tag in used_tags:
            raise LibvirtProjectionError(f"VM virtiofs mount tag {mount_tag!r} is already used")
        filesystem = ET.SubElement(devices, "filesystem", {"type": "mount", "accessmode": "passthrough"})
        ET.SubElement(filesystem, "driver", {"type": "virtiofs"})
        ET.SubElement(filesystem, "source", {"dir": resource["path"]})
        ET.SubElement(filesystem, "target", {"dir": mount_tag})
        if attachment["access"] == "read":
            ET.SubElement(filesystem, "readonly")
        used_tags.add(mount_tag)


def _pci_attributes(selector: str) -> dict[str, str]:
    match = _PCI.fullmatch(selector)
    if not match:
        raise LibvirtProjectionError(f"invalid explicit PCI selector {selector!r}")
    return {
        "domain": f"0x{match.group('domain').lower()}",
        "bus": f"0x{match.group('bus').lower()}",
        "slot": f"0x{match.group('slot').lower()}",
        "function": f"0x{match.group('function').lower()}",
    }


def _hostdev_sources(devices: ET.Element) -> set[tuple[str, str, str, str]]:
    found: set[tuple[str, str, str, str]] = set()
    for hostdev in devices.findall("hostdev"):
        if hostdev.get("type") != "pci":
            continue
        address = hostdev.find("source/address")
        if address is None:
            continue
        found.add(
            (
                address.get("domain", "").lower(),
                address.get("bus", "").lower(),
                address.get("slot", "").lower(),
                address.get("function", "").lower(),
            )
        )
    return found


def _add_accelerators(service: dict[str, Any], root: ET.Element) -> None:
    accelerators = service["resources"]["accelerators"]
    if not accelerators:
        return
    devices = _devices(root)
    existing = _hostdev_sources(devices)
    for accelerator in accelerators:
        selector = accelerator.get("device")
        if accelerator["mode"] != "passthrough" or not isinstance(selector, str):
            raise LibvirtProjectionError("VM accelerators require passthrough mode and an explicit PCI selector")
        attributes = _pci_attributes(selector)
        key = (
            attributes["domain"],
            attributes["bus"],
            attributes["slot"],
            attributes["function"],
        )
        if key in existing:
            raise LibvirtProjectionError(f"VM PCI device {selector!r} is already present in domain XML")
        hostdev = ET.SubElement(devices, "hostdev", {"mode": "subsystem", "type": "pci", "managed": "yes"})
        source = ET.SubElement(hostdev, "source")
        ET.SubElement(source, "address", attributes)
        existing.add(key)


def render_domain_xml(
    effective: dict[str, Any],
    service_id: str,
    service: dict[str, Any],
) -> tuple[pathlib.Path, str, bytes]:
    """Return source path, domain name, and V2-derived transient domain XML."""
    if service["runtime"]["type"] != "vm":
        raise LibvirtProjectionError(f"service {service_id!r} is not a VM runtime")
    if service["workload"]["kind"] != "daemon":
        raise LibvirtProjectionError(f"VM service {service_id!r} currently supports daemon workloads only")
    if service["credentials"]:
        raise LibvirtProjectionError(f"VM service {service_id!r} credential projection is not implemented")
    if service.get("network") is not None or service.get("networkProfile") is not None:
        raise LibvirtProjectionError(f"VM service {service_id!r} V2 network projection is not implemented")
    scalar_resources = {
        key
        for key in ("cpuQuotaPercent", "memoryHighBytes", "memoryMaxBytes", "pidsMax")
        if key in service["resources"]
    }
    if scalar_resources:
        raise LibvirtProjectionError(
            f"VM service {service_id!r} scalar resource projection is not implemented for: "
            f"{', '.join(sorted(scalar_resources))}"
        )
    if service["sandbox"]["mode"] != "inherit":
        raise LibvirtProjectionError(f"VM service {service_id!r} must use runtime-native sandbox inheritance")

    source_path, root = _source(service_id, service)
    name = _domain_name(root)
    _add_storage(effective, service, root)
    _add_accelerators(service, root)
    ET.indent(root, space="  ")
    rendered = ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"
    return source_path, name, rendered


def validate_domain_xml(content: bytes, *, validator_bin: str) -> None:
    """Validate one derived domain XML document with libvirt's native schema validator."""
    validator = pathlib.PurePosixPath(validator_bin)
    if not validator.is_absolute() or ".." in validator.parts:
        raise LibvirtProjectionError("virt-xml-validate must be an absolute safe path")
    with tempfile.TemporaryDirectory(prefix="nas-v2-libvirt-validate-") as raw_tmp:
        candidate = pathlib.Path(raw_tmp) / "domain.xml"
        candidate.write_bytes(content)
        result = subprocess.run(
            [validator_bin, str(candidate)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise LibvirtProjectionError(f"virt-xml-validate rejected derived domain XML: {detail}")


def _load_config(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LibvirtProjectionError(f"unable to read VM lifecycle descriptor {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LibvirtProjectionError("VM lifecycle descriptor must contain an object")
    for key in ("virsh", "domain", "xml"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise LibvirtProjectionError(f"VM lifecycle descriptor requires {key}")
    virsh = pathlib.PurePosixPath(value["virsh"])
    xml = pathlib.PurePosixPath(value["xml"])
    if not virsh.is_absolute() or ".." in virsh.parts:
        raise LibvirtProjectionError("virsh must be an absolute safe path")
    if not xml.is_absolute() or ".." in xml.parts:
        raise LibvirtProjectionError("VM XML path must be an absolute safe path")
    timeout = value.get("shutdownTimeoutSeconds", 180)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1 or timeout > 3600:
        raise LibvirtProjectionError("shutdownTimeoutSeconds must be an integer from 1 to 3600")
    return value


def _run(virsh: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [virsh, *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:2000]
        raise LibvirtProjectionError(f"virsh {' '.join(args)} failed: {detail}")
    return result


def start_domain(config: dict[str, Any]) -> None:
    """Start the V2-derived XML as a transient libvirt domain."""
    _run(config["virsh"], "create", config["xml"])


def stop_domain(config: dict[str, Any]) -> None:
    """Request graceful shutdown and wait; never force-destroy the guest."""
    virsh = config["virsh"]
    domain = config["domain"]
    state = _run(virsh, "domstate", domain, check=False)
    if state.returncode != 0:
        return
    _run(virsh, "shutdown", domain)
    deadline = time.monotonic() + config.get("shutdownTimeoutSeconds", 180)
    while time.monotonic() < deadline:
        state = _run(virsh, "domstate", domain, check=False)
        if state.returncode != 0 or state.stdout.strip().lower() in {"shut off", "shutoff"}:
            return
        time.sleep(0.5)
    raise LibvirtProjectionError(f"VM {domain!r} did not shut down gracefully before the timeout")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one finite Managed Services V2 libvirt lifecycle action")
    parser.add_argument("action", choices=("start", "stop"))
    parser.add_argument("--config", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        config = _load_config(args.config)
        if args.action == "start":
            start_domain(config)
        else:
            stop_domain(config)
        return 0
    except LibvirtProjectionError as exc:
        sys.stderr.write(f"nas-v2-libvirt: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "LibvirtProjectionError",
    "render_domain_xml",
    "start_domain",
    "stop_domain",
    "validate_domain_xml",
]
