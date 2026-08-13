#!/usr/bin/env python3
"""Resolve Managed Services V2 accelerator requests — delegated to Nix hardware.

The heavy vendor/CDI/device selection is now owned by NixOS
`hardware.nvidia` / `hardware.opengl` and `virtualisation.oci-containers`
with `nvidia-container-toolkit`. This module only validates the
generic V2 shape and passes the request through; the Nix side
emits `DeviceAllow` / `CDI` via `systemd` and `podman`.
"""

from __future__ import annotations

import copy
import json
import pathlib
import re
from typing import Any


class AcceleratorResolutionError(RuntimeError):
    pass


_CDI_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*=[A-Za-z0-9][A-Za-z0-9_.:-]*$")


def load_platform_inventory(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceleratorResolutionError(f"unable to read platform inventory {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise AcceleratorResolutionError("platform inventory must be a schemaVersion 1 object")
    return value


def enabled_capabilities(inventory: dict[str, Any]) -> set[str]:
    caps = inventory.get("capabilities", {})
    if not isinstance(caps, dict):
        raise AcceleratorResolutionError("platform inventory capabilities must be an object")
    return {k for k, v in caps.items() if isinstance(k, str) and v is True}


def is_cdi_selector(value: str) -> bool:
    return _CDI_RE.fullmatch(value) is not None


def _vendor_available(vendor: str, inventory: dict[str, Any]) -> bool:
    caps = inventory.get("capabilities", {})
    acc = inventory.get("accelerators", {})
    if not isinstance(caps, dict):
        caps = {}
    if not isinstance(acc, dict):
        acc = {}
    if vendor == "any":
        for v in ("NVIDIA", "AMD", "Intel"):
            if caps.get(f"gpu-{v.lower()}") is True or v in acc:
                # Check if that vendor actually has selectors or is marked configured
                vend = acc.get(v)
                if isinstance(vend, dict) and vend.get("selectors"):
                    return True
                if caps.get(f"gpu-{v.lower()}") is True:
                    return True
        return False
    # specific vendor
    if caps.get(f"gpu-{vendor.lower()}") is True:
        return True
    vend = acc.get(vendor)
    if isinstance(vend, dict) and vend.get("selectors"):
        return True
    return False


def resolve_service_accelerators(
    service_id: str,
    service: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    runtime = service.get("runtime", {})
    rtype = runtime.get("type") if isinstance(runtime, dict) else None
    if not isinstance(rtype, str):
        raise AcceleratorResolutionError(f"service {service_id!r} is missing runtime type")
    out: list[dict[str, Any]] = []
    for idx, req in enumerate(service.get("resources", {}).get("accelerators", [])):
        if not isinstance(req, dict) or req.get("kind") != "gpu":
            raise AcceleratorResolutionError(f"service {service_id!r} accelerator {idx} is invalid")
        if req.get("mode", "shared") not in {"shared", "passthrough"}:
            raise AcceleratorResolutionError(f"invalid mode {req.get('mode')!r}")
        if req.get("vendor", "any") not in {"any", "NVIDIA", "AMD", "Intel"}:
            raise AcceleratorResolutionError(f"invalid vendor {req.get('vendor')!r}")
        # Explicit device passthrough: Nix will handle, always pass through
        if isinstance(req.get("device"), str):
            out.append(copy.deepcopy(req))
            continue
        vendor = req.get("vendor", "any")
        required = bool(req.get("required", False))
        available = _vendor_available(vendor, inventory)
        if not available:
            if required:
                raise AcceleratorResolutionError(
                    f"service {service_id!r} requires unavailable GPU request {idx} (vendor={vendor})"
                )
            continue
        out.append(copy.deepcopy(req))
    return out


def resolve_effective(effective: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(effective)
    services = result.get("services")
    if not isinstance(services, dict):
        raise AcceleratorResolutionError("compiled effective state is missing services")
    derived = result.setdefault("derived", {})
    if not isinstance(derived, dict):
        raise AcceleratorResolutionError("compiled effective state has invalid derived")
    resolved: dict[str, list[dict[str, Any]]] = {}
    for sid in sorted(services):
        svc = services[sid]
        if not isinstance(svc, dict):
            raise AcceleratorResolutionError(f"service {sid!r} is invalid")
        resolved[sid] = resolve_service_accelerators(sid, svc, inventory)
    derived["accelerators"] = resolved
    return result


__all__ = [
    "AcceleratorResolutionError",
    "enabled_capabilities",
    "is_cdi_selector",
    "load_platform_inventory",
    "resolve_effective",
    "resolve_service_accelerators",
]
