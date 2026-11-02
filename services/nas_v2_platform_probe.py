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
_NVIDIA_CDI_RE = re.compile(r"^nvidia\.com/gpu=([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})$")


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


def _listed_nvidia_cdi_devices(tool: str) -> set[str]:
    """List NVIDIA CDI device names via `nvidia-ctk cdi list`.

    Returns an empty set when the toolkit is absent, the command times out,
    or the invocation fails — the caller decides how to treat an empty list.
    """
    try:
        result = subprocess.run(
            [tool, "cdi", "list", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if result.returncode != 0:
        return set()
    try:
        data = json.loads(result.stdout)
    except (ValueError, json.JSONDecodeError):
        return set()
    devices: set[str] = set()
    if isinstance(data, dict):
        for entry in data.get("devices", []):
            if isinstance(entry, dict):
                name = entry.get("name")
                if isinstance(name, str):
                    devices.add(name)
    return devices


def _check_duplicate_gpu_identities(selectors: list[dict[str, Any]]) -> None:
    """Reject NVIDIA selectors that collide on minor number or CDI UUID.

    Two records sharing the same device minor (or the same CDI UUID) denote
    an ambiguous GPU identity and must fail closed rather than silently
    selecting the wrong device.
    """
    seen_minors: set[int] = set()
    seen_uuids: set[str] = set()
    for sel in selectors:
        if sel.get("type") == "devices":
            for value in sel.get("values", []):
                match = _NVIDIA_DEVICE_RE.fullmatch(pathlib.PurePosixPath(value).name)
                if match is not None:
                    minor = int(match.group(1))
                    if minor in seen_minors:
                        raise PlatformProbeError(f"duplicate NVIDIA GPU minor: nvidia{minor}")
                    seen_minors.add(minor)
        elif sel.get("type") == "cdi":
            match = _NVIDIA_CDI_RE.fullmatch(sel.get("value", ""))
            if match is not None:
                uuid = match.group(1)
                if uuid in seen_uuids:
                    raise PlatformProbeError(f"duplicate NVIDIA CDI UUID: {uuid}")
                seen_uuids.add(uuid)


def probe_inventory(
    base: dict[str, Any],
    *,
    sys_class_drm: pathlib.Path = pathlib.Path("/sys/class/drm"),
    dev_root: pathlib.Path = pathlib.Path("/dev"),
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
    for index in sorted(set(nvidia_indexes)):
        gpu_node = dev_root / f"nvidia{index}"
        selectors["NVIDIA"].append(_devices([gpu_node, *shared_nvidia]))
        if capabilities.get("gpu-nvidia-cdi") is True:
            selectors["NVIDIA"].append(_cdi(f"nvidia.com/gpu={index}"))
    if not nvidia_indexes:
        selectors["NVIDIA"].extend(drm_selectors["NVIDIA"])

    _check_duplicate_gpu_identities(selectors["NVIDIA"])

    accelerators: dict[str, Any] = {}
    for vendor in ("NVIDIA", "AMD", "Intel"):
        configured = capabilities.get(f"gpu-{vendor.lower()}") is True
        available = selectors[vendor]
        accelerators[vendor] = {
            "configured": configured,
            "selectors": available,
        }
        if vendor == "NVIDIA" and capabilities.get("gpu-nvidia-cdi") is True and nvidia_indexes:
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
            ),
        )
    except PlatformProbeError as exc:
        print(f"nas-v2-platform-probe: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
