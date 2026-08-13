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
    capabilities = value.get("capabilities")
    if not isinstance(capabilities, dict):
        raise AcceleratorResolutionError("platform inventory capabilities must be an object")
    accelerators = value.get("accelerators", {})
    if not isinstance(accelerators, dict):
        raise AcceleratorResolutionError("platform inventory accelerators must be an object")
    return value


def enabled_capabilities(inventory: dict[str, Any]) -> set[str]:
    capabilities = inventory.get("capabilities", {})
    if not isinstance(capabilities, dict):
        raise AcceleratorResolutionError("platform inventory capabilities must be an object")
    return {key for key, enabled in capabilities.items() if isinstance(key, str) and enabled is True}


def is_cdi_selector(value: str) -> bool:
    return _CDI_RE.fullmatch(value) is not None


def _device_path(value: str) -> str | None:
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() and ".." not in path.parts and str(path).startswith("/dev/"):
        return str(path)
    return None


def _selector(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    kind = value.get("type")
    if kind == "devices":
        raw_values = value.get("values")
        if not isinstance(raw_values, list) or not raw_values:
            return None
        devices: list[str] = []
        for raw in raw_values:
            if not isinstance(raw, str):
                return None
            parsed = _device_path(raw)
            if parsed is None:
                return None
            if parsed not in devices:
                devices.append(parsed)
        return {"type": "devices", "values": devices}
    raw = value.get("value")
    if kind == "device" and isinstance(raw, str):
        parsed = _device_path(raw)
        return None if parsed is None else {"type": "devices", "values": [parsed]}
    if kind == "cdi" and isinstance(raw, str) and is_cdi_selector(raw):
        return {"type": "cdi", "value": raw}
    return None


def _selector_sort_value(selector: dict[str, Any]) -> str:
    if selector["type"] == "cdi":
        return str(selector["value"])
    return "\0".join(selector["values"])


def _vendor_inventory(
    inventory: dict[str, Any],
    vendor: str,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    raw_all = inventory.get("accelerators", {})
    raw_vendor = raw_all.get(vendor) if isinstance(raw_all, dict) else None
    if not isinstance(raw_vendor, dict):
        return [], None
    selectors: list[dict[str, Any]] = []
    for value in raw_vendor.get("selectors", []):
        parsed = _selector(value)
        if parsed is not None and parsed not in selectors:
            selectors.append(parsed)
    return selectors, _selector(raw_vendor.get("allSelector"))


def _runtime_selector_preference(runtime_type: str) -> tuple[str, ...]:
    if runtime_type in {"compose", "oci", "quadlet"}:
        return ("cdi", "devices")
    if runtime_type in {"systemd", "exec", "python", "session-oci"}:
        return ("devices",)
    return ()


def _filter_selectors(selectors: list[dict[str, Any]], runtime_type: str) -> list[dict[str, Any]]:
    preferences = _runtime_selector_preference(runtime_type)
    return sorted(
        (selector for selector in selectors if selector["type"] in preferences),
        key=lambda selector: (preferences.index(selector["type"]), _selector_sort_value(selector)),
    )


def _explicit_selector(device: str, runtime_type: str) -> dict[str, Any]:
    if device.startswith("/dev/"):
        parsed = _selector({"type": "device", "value": device})
    elif is_cdi_selector(device):
        parsed = _selector({"type": "cdi", "value": device})
    else:
        parsed = None
    if parsed is None:
        raise AcceleratorResolutionError(f"invalid shared GPU device selector {device!r}")
    if parsed["type"] not in _runtime_selector_preference(runtime_type):
        raise AcceleratorResolutionError(
            f"{runtime_type} runtime cannot faithfully lower {parsed['type']} accelerator selector {device!r}"
        )
    return parsed


def _select_vendor(
    inventory: dict[str, Any],
    requested: str,
    runtime_type: str,
) -> tuple[str | None, list[dict[str, Any]], dict[str, Any] | None]:
    candidates = _VENDOR_ORDER if requested == "any" else (requested,)
    for vendor in candidates:
        selectors, all_selector = _vendor_inventory(inventory, vendor)
        supported = _filter_selectors(selectors, runtime_type)
        if supported:
            if all_selector is not None and all_selector["type"] not in _runtime_selector_preference(runtime_type):
                all_selector = None
            return vendor, supported, all_selector
    return None, [], None


def resolve_service_accelerators(
    service_id: str,
    service: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    runtime = service.get("runtime", {})
    runtime_type = runtime.get("type") if isinstance(runtime, dict) else None
    if not isinstance(runtime_type, str):
        raise AcceleratorResolutionError(f"service {service_id!r} is missing its runtime type")

    selector_runtime_type = runtime_type
    if runtime_type == "oci" and service.get("workload", {}).get("kind") == "session":
        selector_runtime_type = "session-oci"

    resolved: list[dict[str, Any]] = []
    raw_accelerators = service.get("resources", {}).get("accelerators", [])
    for index, request in enumerate(raw_accelerators):
        if not isinstance(request, dict) or request.get("kind") != "gpu":
            raise AcceleratorResolutionError(f"service {service_id!r} accelerator {index} is invalid")
        if runtime_type == "vm":
            resolved.append(copy.deepcopy(request))
            continue
        if request.get("mode", "shared") != "shared":
            raise AcceleratorResolutionError(
                f"service {service_id!r} accelerator {index} passthrough is valid only for VM runtimes"
            )

        quantity = request.get("quantity", 1)
        explicit = request.get("device")
        if isinstance(explicit, str):
            if quantity != 1:
                raise AcceleratorResolutionError(
                    f"service {service_id!r} accelerator {index} with explicit device must use quantity=1"
                )
            selectors = [_explicit_selector(explicit, selector_runtime_type)]
            vendor = request.get("vendor", "any")
        else:
            vendor, selectors, all_selector = _select_vendor(
                inventory,
                str(request.get("vendor", "any")),
                selector_runtime_type,
            )
            if quantity == "all" and all_selector is not None:
                selectors = [all_selector]
            elif quantity == "all":
                pass
            elif isinstance(quantity, int) and not isinstance(quantity, bool):
                selectors = selectors[:quantity]
            else:
                raise AcceleratorResolutionError(
                    f"service {service_id!r} accelerator {index} has invalid quantity {quantity!r}"
                )

        enough = bool(selectors) if quantity == "all" else isinstance(quantity, int) and len(selectors) >= quantity
        if not enough:
            if request.get("required", False):
                raise AcceleratorResolutionError(
                    f"service {service_id!r} requires unavailable GPU request {index} "
                    f"(vendor={request.get('vendor', 'any')}, quantity={quantity})"
                )
            continue

        resolved.append(
            {
                "kind": "gpu",
                "vendor": vendor or request.get("vendor", "any"),
                "required": bool(request.get("required", False)),
                "mode": "shared",
                "selectors": selectors,
                **({"target": request["target"]} if "target" in request else {}),
            }
        )
    return resolved


def _materialize_requests(resolved: list[dict[str, Any]]) -> list[dict[str, Any]]:
    materialized: list[dict[str, Any]] = []
    for request in resolved:
        if request.get("mode") == "passthrough":
            materialized.append(copy.deepcopy(request))
            continue
        for selector in request.get("selectors", []):
            values = [selector["value"]] if selector["type"] == "cdi" else selector["values"]
            for value in values:
                materialized.append(
                    {
                        "kind": "gpu",
                        "vendor": request.get("vendor", "any"),
                        "quantity": 1,
                        "required": True,
                        "mode": "shared",
                        "device": value,
                        **({"target": request["target"]} if "target" in request else {}),
                    }
                )
    return materialized


def resolve_effective(effective: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(effective)
    services = result.get("services")
    if not isinstance(services, dict):
        raise AcceleratorResolutionError("compiled effective state is missing services")
    derived = result.setdefault("derived", {})
    if not isinstance(derived, dict):
        raise AcceleratorResolutionError("compiled effective state has invalid derived metadata")
    resolved: dict[str, list[dict[str, Any]]] = {}
    for service_id in sorted(services):
        service = services[service_id]
        if not isinstance(service, dict):
            raise AcceleratorResolutionError(f"compiled service {service_id!r} is invalid")
        service_resolved = resolve_service_accelerators(service_id, service, inventory)
        resolved[service_id] = service_resolved
        resources = service.get("resources")
        if not isinstance(resources, dict):
            raise AcceleratorResolutionError(f"compiled service {service_id!r} has invalid resources")
        resources["accelerators"] = _materialize_requests(service_resolved)
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
