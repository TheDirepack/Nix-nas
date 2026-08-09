#!/usr/bin/env python3
"""Generic device-resource resolution for Managed Services V2.

Service definitions describe GPU intent as data in ``resources.gpus``. This
module resolves that intent into runtime-neutral CDI names, device nodes, and
PCI addresses. Runtime adapters consume the same resolved structure; there are
no application-name checks here.

Supported selectors:

- ``optional:auto`` / ``required:auto``: first available GPU
- ``optional:all`` / ``required:all``: every available GPU
- ``optional:nvidia:all`` / ``required:nvidia:all``
- ``optional:amd:all`` / ``required:amd:all``
- ``optional:intel:all`` / ``required:intel:all``
- ``optional:pci:0000:01:00.0`` / ``required:pci:...``
- ``optional:cdi:nvidia.com/gpu=all`` / ``required:cdi:...``

The requirement prefix is explicit so CPU-capable workloads can request a GPU
when present without making the whole service unavailable on GPU-less hosts.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

from nas_managed_resources import ManagedResourceError

GPU_VENDORS = {
    "0x10de": "nvidia",
    "0x1002": "amd",
    "0x8086": "intel",
}
GPU_SELECTOR_RE = re.compile(
    r"^(optional|required):(auto|all|(?:nvidia|amd|intel):all|pci:[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]|cdi:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+=[A-Za-z0-9_.:@-]+)$"
)
PCI_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")


def normalize_gpu_requests(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ManagedResourceError("resources.gpus must be an array of V2 GPU selector strings")
    if len(value) != len(set(value)):
        raise ManagedResourceError("resources.gpus contains duplicate selectors")
    normalized: list[str] = []
    for selector in value:
        if GPU_SELECTOR_RE.fullmatch(selector) is None:
            raise ManagedResourceError(f"Invalid V2 GPU selector {selector!r}")
        normalized.append(selector)
    return normalized


def _pci_from_device_link(link: pathlib.Path) -> str | None:
    try:
        resolved = link.resolve(strict=True)
    except OSError:
        return None
    for part in reversed(resolved.parts):
        if PCI_RE.fullmatch(part):
            return part.lower()
    return None


def discover_gpus(*, sys_class_drm: pathlib.Path = pathlib.Path("/sys/class/drm"), dev_root: pathlib.Path = pathlib.Path("/dev")) -> list[dict[str, Any]]:
    """Return stable GPU inventory from DRM/sysfs without vendor-specific daemons."""

    by_pci: dict[str, dict[str, Any]] = {}
    if sys_class_drm.is_dir():
        for entry in sorted(sys_class_drm.iterdir(), key=lambda path: path.name):
            if not (entry.name.startswith("renderD") or re.fullmatch(r"card\d+", entry.name)):
                continue
            pci = _pci_from_device_link(entry / "device")
            if pci is None:
                continue
            try:
                vendor_id = (entry / "device" / "vendor").read_text(encoding="utf-8").strip().lower()
            except OSError:
                continue
            vendor = GPU_VENDORS.get(vendor_id)
            if vendor is None:
                continue
            node = dev_root / "dri" / entry.name
            record = by_pci.setdefault(
                pci,
                {"pciAddress": pci, "vendor": vendor, "devicePaths": [], "cdiDevices": []},
            )
            if node.exists():
                record["devicePaths"].append(str(node))

    # NVIDIA exposes additional character devices that CUDA/NVML need. Attach
    # them to NVIDIA records generically; CDI remains preferred for containers.
    nvidia_nodes = sorted(
        str(path)
        for pattern in ("nvidiactl", "nvidia-uvm", "nvidia-uvm-tools", "nvidia[0-9]*")
        for path in dev_root.glob(pattern)
        if path.exists()
    )
    nvidia_records = [record for record in by_pci.values() if record["vendor"] == "nvidia"]
    if nvidia_records:
        for record in nvidia_records:
            record["devicePaths"] = sorted(set(record["devicePaths"] + nvidia_nodes))
        # ``all`` is a valid CDI selector and intentionally represents the
        # aggregate request rather than guessing an index-to-PCI mapping.
        for record in nvidia_records:
            record["cdiDevices"] = ["nvidia.com/gpu=all"]

    return [by_pci[key] for key in sorted(by_pci)]


def _merge_devices(records: list[dict[str, Any]], *, request: str, required: bool) -> dict[str, Any]:
    vendors = sorted({str(record["vendor"]) for record in records})
    return {
        "request": request,
        "required": required,
        "vendors": vendors,
        "devicePaths": sorted({path for record in records for path in record.get("devicePaths", [])}),
        "cdiDevices": sorted({name for record in records for name in record.get("cdiDevices", [])}),
        "pciAddresses": sorted({str(record["pciAddress"]) for record in records}),
    }


def resolve_gpu_requests(requests: Any, *, inventory: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    selectors = normalize_gpu_requests(requests)
    if not selectors:
        return []
    available = discover_gpus() if inventory is None else inventory
    resolved: list[dict[str, Any]] = []

    for selector in selectors:
        requirement, expression = selector.split(":", 1)
        required = requirement == "required"
        selected: list[dict[str, Any]] = []
        explicit_cdi: list[str] = []

        if expression == "auto":
            selected = available[:1]
        elif expression == "all":
            selected = list(available)
        elif expression in {"nvidia:all", "amd:all", "intel:all"}:
            vendor = expression.split(":", 1)[0]
            selected = [record for record in available if record.get("vendor") == vendor]
        elif expression.startswith("pci:"):
            pci = expression.removeprefix("pci:").lower()
            selected = [record for record in available if str(record.get("pciAddress", "")).lower() == pci]
        elif expression.startswith("cdi:"):
            explicit_cdi = [expression.removeprefix("cdi:")]
        else:  # pragma: no cover - guarded by normalize_gpu_requests
            raise ManagedResourceError(f"Unhandled GPU selector {selector!r}")

        if not selected and not explicit_cdi:
            if required:
                raise ManagedResourceError(f"Required GPU selector {selector!r} matched no host GPU")
            resolved.append(
                {
                    "request": selector,
                    "required": False,
                    "vendors": [],
                    "devicePaths": [],
                    "cdiDevices": [],
                    "pciAddresses": [],
                }
            )
            continue

        record = _merge_devices(selected, request=selector, required=required)
        if explicit_cdi:
            record["cdiDevices"] = explicit_cdi
        resolved.append(record)
    return resolved


def resolve_service_devices(service: dict[str, Any], *, inventory: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    resources = service.get("resources") or {}
    if not isinstance(resources, dict):
        raise ManagedResourceError("service resources must be an object")
    return resolve_gpu_requests(resources.get("gpus", []), inventory=inventory)


def flattened_device_paths(resolved: list[dict[str, Any]]) -> list[str]:
    return sorted({path for item in resolved for path in item.get("devicePaths", [])})


def flattened_cdi_devices(resolved: list[dict[str, Any]]) -> list[str]:
    return sorted({name for item in resolved for name in item.get("cdiDevices", [])})


def flattened_pci_addresses(resolved: list[dict[str, Any]]) -> list[str]:
    return sorted({address for item in resolved for address in item.get("pciAddresses", [])})
