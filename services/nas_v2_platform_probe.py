#!/usr/bin/env python3
"""Build the finite runtime platform inventory for Managed Services V2.

The immutable Nix-generated base inventory describes configured capabilities.
This helper adds concrete host GPU selectors from sysfs/devfs immediately before
V2 compilation. It is a finite probe, not a controller, and records no secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any


class PlatformProbeError(RuntimeError):
    """Raised when the immutable platform inventory cannot be probed safely."""


_VENDOR_IDS = {
    "0x1002": "AMD",
    "0x8086": "Intel",
    "0x10de": "NVIDIA",
}
_NVIDIA_DEVICE_RE = re.compile(r"^nvidia([0-9]+)$")
_NVIDIA_SHARED_NODES = ("nvidiactl", "nvidia-uvm", "nvidia-uvm-tools", "nvidia-modeset")
_NVIDIA_UUID_RE = re.compile(r"GPU-[0-9a-fA-F-]{8,}")


def _nvidia_gpu_uuids_by_minor(proc_nvidia_gpus: pathlib.Path) -> dict[int, str]:
    """Read stable GPU identities from the NVIDIA driver, not GPU list indices.

    Each /proc/driver/nvidia/gpus/*/information entry contains both
    "Device Minor" (/dev/nvidiaN) and "GPU UUID" (the CDI UUID selector).
    Missing/unreadable entries do not justify guessing the mapping.
    """
    identities: dict[int, str] = {}
    seen_uuids: set[str] = set()
    try:
        information_files = sorted(proc_nvidia_gpus.glob("*/information"))
    except OSError as exc:
        raise PlatformProbeError(f"unable to enumerate NVIDIA GPU identities: {exc}") from exc
    for path in information_files:
        try:
            lines = path.read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeError):
            continue
        fields = dict(line.split(":", 1) for line in lines if ":" in line)
        minor_text = fields.get("Device Minor", "").strip()
        uuid = fields.get("GPU UUID", "").strip()
        if not minor_text.isdecimal() or _NVIDIA_UUID_RE.fullmatch(uuid) is None:
            continue
        minor = int(minor_text)
        if minor > 254:
            continue
        if minor in identities or uuid in seen_uuids:
            raise PlatformProbeError("duplicate NVIDIA GPU minor or UUID in driver metadata")
        identities[minor] = uuid
        seen_uuids.add(uuid)
    return identities


def _listed_nvidia_cdi_devices(nvidia_ctk_bin: str) -> set[str]:
    """Trust only device names reported by the installed CDI provider."""
    try:
        result = subprocess.run(
            [nvidia_ctk_bin, "cdi", "list"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if result.returncode != 0:
        return set()
    return {
        name
        for line in result.stdout.splitlines()
        if (name := line.strip()).startswith("nvidia.com/gpu=")
    }


def _load_base(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PlatformProbeError(f"unable to read base platform inventory {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise PlatformProbeError("base platform inventory must be a schemaVersion 1 object")
    capabilities = value.get("capabilities")
    if not isinstance(capabilities, dict) or not all(
        isinstance(key, str) and isinstance(enabled, bool) for key, enabled in capabilities.items()
    ):
        raise PlatformProbeError("base platform inventory capabilities must be a boolean object")
    return value


def _cdi(value: str) -> dict[str, str]:
    return {"type": "cdi", "value": value}


def _devices(values: list[pathlib.Path]) -> dict[str, Any]:
    return {"type": "devices", "values": [str(path) for path in values]}


def probe_inventory(
    base: dict[str, Any],
    *,
    sys_class_drm: pathlib.Path = pathlib.Path("/sys/class/drm"),
    dev_root: pathlib.Path = pathlib.Path("/dev"),
    proc_nvidia_gpus: pathlib.Path = pathlib.Path("/proc/driver/nvidia/gpus"),
    cdi_device_names: set[str] | None = None,
    nvidia_ctk_bin: str = "nvidia-ctk",
) -> dict[str, Any]:
    capabilities = dict(base["capabilities"])
    drm_selectors: dict[str, list[dict[str, Any]]] = {"NVIDIA": [], "AMD": [], "Intel": []}

    try:
        render_nodes = sorted(sys_class_drm.glob("renderD*"))
    except OSError as exc:
        raise PlatformProbeError(f"unable to enumerate DRM render devices: {exc}") from exc
    for node in render_nodes:
        try:
            vendor_id = (node / "device" / "vendor").read_text(encoding="ascii").strip().lower()
        except (OSError, UnicodeError):
            continue
        vendor = _VENDOR_IDS.get(vendor_id)
        device = dev_root / "dri" / node.name
        if vendor is None or not device.exists():
            continue
        drm_selectors[vendor].append(_devices([device]))

    nvidia_indexes: list[int] = []
    try:
        nvidia_entries = list(dev_root.glob("nvidia*"))
    except OSError as exc:
        raise PlatformProbeError(f"unable to enumerate NVIDIA devices: {exc}") from exc
    for entry in nvidia_entries:
        match = _NVIDIA_DEVICE_RE.fullmatch(entry.name)
        if match is not None and entry.exists():
            nvidia_indexes.append(int(match.group(1)))

    selectors: dict[str, list[dict[str, Any]]] = {
        "NVIDIA": [],
        "AMD": drm_selectors["AMD"],
        "Intel": drm_selectors["Intel"],
    }
    shared_nvidia = [dev_root / name for name in _NVIDIA_SHARED_NODES if (dev_root / name).exists()]
    cdi_enabled = capabilities.get("gpu-nvidia-cdi") is True and bool(nvidia_indexes)
    if cdi_enabled:
        identities = _nvidia_gpu_uuids_by_minor(proc_nvidia_gpus)
        listed_cdi = _listed_nvidia_cdi_devices(nvidia_ctk_bin) if cdi_device_names is None else set(cdi_device_names)
    else:
        identities = {}
        listed_cdi = set()
    for minor in sorted(set(nvidia_indexes)):
        gpu_node = dev_root / f"nvidia{minor}"
        selectors["NVIDIA"].append(_devices([gpu_node, *shared_nvidia]))
        uuid = identities.get(minor)
        if uuid is not None and f"nvidia.com/gpu={uuid}" in listed_cdi:
            selectors["NVIDIA"].append(_cdi(f"nvidia.com/gpu={uuid}"))
    if not nvidia_indexes:
        selectors["NVIDIA"].extend(drm_selectors["NVIDIA"])

    accelerators: dict[str, Any] = {}
    for vendor in ("NVIDIA", "AMD", "Intel"):
        configured = capabilities.get(f"gpu-{vendor.lower()}") is True
        available = selectors[vendor]
        accelerators[vendor] = {
            "configured": configured,
            "selectors": available,
        }
        if vendor == "NVIDIA" and "nvidia.com/gpu=all" in listed_cdi:
            accelerators[vendor]["allSelector"] = _cdi("nvidia.com/gpu=all")

    return {
        "schemaVersion": 1,
        "capabilities": capabilities,
        "accelerators": accelerators,
    }


def _atomic_write(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(raw)
    replaced = False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        replaced = True
    finally:
        if not replaced:
            temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--sys-class-drm", type=pathlib.Path, default=pathlib.Path("/sys/class/drm"))
    parser.add_argument("--dev-root", type=pathlib.Path, default=pathlib.Path("/dev"))
    parser.add_argument("--nvidia-ctk-bin", default="nvidia-ctk")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _atomic_write(
            args.output,
            probe_inventory(
                _load_base(args.base),
                sys_class_drm=args.sys_class_drm,
                dev_root=args.dev_root,
                nvidia_ctk_bin=args.nvidia_ctk_bin,
            ),
        )
    except PlatformProbeError as exc:
        print(f"nas-v2-platform-probe: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
