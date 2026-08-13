#!/usr/bin/env python3
"""Resolve generic Managed Services V2 accelerator requests against host inventory."""

from __future__ import annotations

import copy
import json
import pathlib
import re
from typing import Any


class AcceleratorResolutionError(RuntimeError):
    """Raised when an accelerator request cannot be satisfied faithfully."""


_CDI_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*=[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_VENDOR_ORDER = ("NVIDIA", "AMD", "Intel")


def load_platform_inventory(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceleratorResolutionError(f"unable to read platform inventory {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise AcceleratorResolutionError("platform inventory must be a schemaVersion 1 object")
    if not isinstance(value.get("capabilities"), dict):
        raise AcceleratorResolutionError("platform inventory capabilities must be an object")
    if not isinstance(value.get("accelerators", {}), dict):
        raise AcceleratorResolutionError("platform inventory accelerators must be an object")
    return value


def enabled_capabilities(inventory: dict[str, Any]) -> set[str]:
    caps = inventory.get("capabilities", {})
    if not isinstance(caps, dict):
        raise AcceleratorResolutionError("platform inventory capabilities must be an object")
    return {k for k, v in caps.items() if isinstance(k, str) and v is True}


def is_cdi_selector(value: str) -> bool:
    return _CDI_RE.fullmatch(value) is not None


def _selector(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    kind = value.get("type")
    if kind == "devices":
        vals = value.get("values")
        if not isinstance(vals, list) or not vals:
            return None
        devs: list[str] = []
        for raw in vals:
            if not isinstance(raw, str):
                return None
            p = pathlib.PurePosixPath(raw)
            if not (p.is_absolute() and ".." not in p.parts and str(p).startswith("/dev/")):
                return None
            s = str(p)
            if s not in devs:
                devs.append(s)
        return {"type": "devices", "values": devs}
    raw = value.get("value")
    if kind == "device" and isinstance(raw, str):
        p = pathlib.PurePosixPath(raw)
        if p.is_absolute() and ".." not in p.parts and str(p).startswith("/dev/"):
            return {"type": "devices", "values": [str(p)]}
        return None
    if kind == "cdi" and isinstance(raw, str) and is_cdi_selector(raw):
        return {"type": "cdi", "value": raw}
    return None


def _runtime_selector_preference(rt: str) -> tuple[str, ...]:
    return (
        ("cdi", "devices")
        if rt in {"compose", "oci", "quadlet"}
        else ("devices",)
        if rt in {"systemd", "exec", "python", "session-oci"}
        else ()
    )


def _select_vendor(
    inventory: dict[str, Any], requested: str, rt: str
) -> tuple[str | None, list[dict[str, Any]], dict[str, Any] | None]:
    cands = _VENDOR_ORDER if requested == "any" else (requested,)
    pref = _runtime_selector_preference(rt)
    for vendor in cands:
        raw_all = inventory.get("accelerators", {})
        raw_vendor = raw_all.get(vendor) if isinstance(raw_all, dict) else None
        if not isinstance(raw_vendor, dict):
            continue
        sels: list[dict[str, Any]] = []
        for v in raw_vendor.get("selectors", []):
            parsed = _selector(v)
            if parsed is None or parsed["type"] not in pref or parsed in sels:
                continue
            sels.append(parsed)
        sels.sort(key=lambda s: (pref.index(s["type"]), s["value"] if s["type"] == "cdi" else "\0".join(s["values"])))
        if sels:
            all_sel = _selector(raw_vendor.get("allSelector"))
            if all_sel is not None and all_sel["type"] not in pref:
                all_sel = None
            return vendor, sels, all_sel
    return None, [], None


# fmt: off
def resolve_service_accelerators(service_id: str, service: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, Any]]:
    sid = service_id
    rt = service.get("runtime", {})
    rt_type = rt.get("type") if isinstance(rt, dict) else None
    if not isinstance(rt_type, str):
        raise AcceleratorResolutionError(f"service {sid!r} is missing its runtime type")
    sel_rt = "session-oci" if rt_type == "oci" and service.get("workload", {}).get("kind") == "session" else rt_type
    resolved: list[dict[str, Any]] = []
    for idx, req in enumerate(service.get("resources", {}).get("accelerators", [])):
        if not isinstance(req, dict) or req.get("kind") != "gpu":
            raise AcceleratorResolutionError(f"service {sid!r} accelerator {idx} is invalid")
        if rt_type == "vm":
            resolved.append(copy.deepcopy(req))
            continue
        if req.get("mode", "shared") != "shared":
            raise AcceleratorResolutionError(f"service {sid!r} accelerator {idx} passthrough is valid only for VM runtimes")
        qty = req.get("quantity", 1)
        dev = req.get("device")
        if isinstance(dev, str):
            if qty != 1:
                raise AcceleratorResolutionError(f"service {sid!r} accelerator {idx} with explicit device must use quantity=1")
            if dev.startswith("/dev/"):
                parsed = _selector({"type": "device", "value": dev})
            elif is_cdi_selector(dev):
                parsed = _selector({"type": "cdi", "value": dev})
            else:
                parsed = None
            if parsed is None:
                raise AcceleratorResolutionError(f"invalid shared GPU device selector {dev!r}")
            if parsed["type"] not in _runtime_selector_preference(sel_rt):
                raise AcceleratorResolutionError(f"{sel_rt} runtime cannot faithfully lower {parsed['type']} accelerator selector {dev!r}")
            sels = [parsed]
            vendor = req.get("vendor", "any")
        else:
            vendor, sels, all_sel = _select_vendor(inventory, str(req.get("vendor", "any")), sel_rt)
            if qty == "all":
                sels = [all_sel] if all_sel is not None else sels
            elif isinstance(qty, int) and not isinstance(qty, bool):
                sels = sels[:qty]
            else:
                raise AcceleratorResolutionError(f"service {sid!r} accelerator {idx} has invalid quantity {qty!r}")
        enough = bool(sels) if qty == "all" else isinstance(qty, int) and len(sels) >= qty
        if not enough:
            if req.get("required", False):
                msg = f"service {sid!r} requires unavailable GPU request {idx} (vendor={req.get('vendor', 'any')}, quantity={qty})"
                raise AcceleratorResolutionError(msg)
            continue
        extra = {"target": req["target"]} if "target" in req else {}
        fv = vendor or req.get("vendor", "any")
        reqd = bool(req.get("required", False))
        d = {"kind": "gpu", "vendor": fv, "required": reqd, "mode": "shared", "selectors": sels}
        d.update(extra)
        resolved.append(d)
    return resolved
# fmt: on


def resolve_effective(effective: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(effective)
    svcs = result.get("services")
    if not isinstance(svcs, dict):
        raise AcceleratorResolutionError("compiled effective state is missing services")
    derived = result.setdefault("derived", {})
    if not isinstance(derived, dict):
        raise AcceleratorResolutionError("compiled effective state has invalid derived metadata")
    resolved: dict[str, list[dict[str, Any]]] = {}
    for sid in sorted(svcs):
        svc = svcs[sid]
        if not isinstance(svc, dict):
            raise AcceleratorResolutionError(f"compiled service {sid!r} is invalid")
        svc_resolved = resolve_service_accelerators(sid, svc, inventory)
        resolved[sid] = svc_resolved
        res = svc.get("resources")
        if not isinstance(res, dict):
            raise AcceleratorResolutionError(f"compiled service {sid!r} has invalid resources")
        mats: list[dict[str, Any]] = []
        for req in svc_resolved:
            if req.get("mode") == "passthrough":
                mats.append(copy.deepcopy(req))
                continue
            extra = {"target": req["target"]} if "target" in req else {}
            rv = req.get("vendor", "any")
            for sel in req.get("selectors", []):
                vals = [sel["value"]] if sel["type"] == "cdi" else sel["values"]
                for v in vals:
                    d = {"kind": "gpu", "vendor": rv, "quantity": 1, "required": True, "mode": "shared", "device": v}
                    d.update(extra)
                    mats.append(d)
        res["accelerators"] = mats
    derived["accelerators"] = resolved
    return result


# fmt: off
__all__ = ["AcceleratorResolutionError", "enabled_capabilities", "is_cdi_selector", "load_platform_inventory", "resolve_effective", "resolve_service_accelerators"]
# fmt: on
