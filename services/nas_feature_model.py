from __future__ import annotations

import pathlib
import threading
import time
import urllib.parse
from typing import Any

VALID_MODES = {"off", "on-demand", "always"}


def valid_loopback_http_url(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "http"
        and host in {"127.0.0.1", "localhost", "::1"}
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and (port is None or 0 < port < 65536)
    )


class WakeCache:
    """Small thread-safe cache shared by authorization-handler threads."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._values: dict[str, float] = {}

    def get(self, feature_id: str, default: float = 0.0) -> float:
        with self._lock:
            return self._values.get(feature_id, default)

    def record(self, feature_id: str, timestamp: float) -> None:
        with self._lock:
            self._values[feature_id] = timestamp

    def pop(self, feature_id: str) -> None:
        with self._lock:
            self._values.pop(feature_id, None)

    def clear(self) -> None:
        with self._lock:
            self._values.clear()


class FeatureError(RuntimeError):
    """Expected feature configuration or activation failure."""


class FeatureFileMissingError(FeatureError):
    """A required feature-state or catalog file does not exist."""


def entry_allowed_modes(entry: dict[str, Any]) -> list[str]:
    raw = entry.get("allowedModes")
    if isinstance(raw, list) and raw:
        return [str(mode) for mode in raw]
    return ["off", "always"]


def entry_default_mode(entry: dict[str, Any]) -> str:
    value = entry.get("defaultMode")
    if isinstance(value, str):
        return value
    return "always" if bool(entry.get("default", False)) else "off"


def reject_unknown_fields(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise FeatureError(f"{label} contains unknown field(s): {', '.join(unknown)}")


def normalize_catalog(
    catalog: dict[str, Any],
    contract: tuple[set[str], set[str], set[str], set[str]],
) -> dict[str, Any]:
    if not isinstance(catalog, dict):
        raise FeatureError("Feature catalog must be an object")
    top_fields, feature_fields, probe_fields, memory_fields = contract
    reject_unknown_fields(catalog, top_fields, "Feature catalog")
    schema = catalog.get("schemaVersion")
    if schema not in {1, 2}:
        raise FeatureError("Unsupported feature catalog schema")
    features = catalog.get("features")
    if not isinstance(features, dict) or not features:
        raise FeatureError("Feature catalog contains no features")
    for feature_id, entry in features.items():
        if not isinstance(feature_id, str) or not isinstance(entry, dict):
            raise FeatureError("Malformed feature catalog entry")
        reject_unknown_fields(entry, feature_fields, f"Feature {feature_id}")
        parent = entry.get("parent")
        if parent is not None and parent not in features:
            raise FeatureError(f"Feature {feature_id} references unknown parent {parent}")
        allowed = entry_allowed_modes(entry)
        if not allowed or any(mode not in VALID_MODES for mode in allowed) or "off" not in allowed:
            raise FeatureError(f"Feature {feature_id} has invalid allowedModes")
        if entry_default_mode(entry) not in allowed:
            raise FeatureError(f"Feature {feature_id} default mode is not allowed")
        if "on-demand" in allowed and int(entry.get("idleSeconds", 0)) <= 0:
            raise FeatureError(f"Feature {feature_id} requires a positive idleSeconds value")
        for field in ("startUnits", "stopUnits"):
            units = entry.get(field, [])
            if not isinstance(units, list) or not all(isinstance(unit, str) and unit for unit in units):
                raise FeatureError(f"Feature {feature_id} has invalid {field}")
        ports = entry.get("activePorts", [])
        if not isinstance(ports, list) or not all(isinstance(port, int) and 0 < port < 65536 for port in ports):
            raise FeatureError(f"Feature {feature_id} has invalid activePorts")
        health_urls = entry.get("healthUrls", [])
        health_url = entry.get("healthUrl")
        if health_url is not None:
            health_urls = [health_url, *health_urls]
        if not isinstance(health_urls, list) or not all(isinstance(url, str) and url for url in health_urls):
            raise FeatureError(f"Feature {feature_id} has invalid healthUrls")
        for url in health_urls:
            if not valid_loopback_http_url(url):
                raise FeatureError(
                    f"Feature {feature_id} health URL must be loopback plain HTTP without credentials or fragments"
                )
        probe = entry.get("availabilityProbe")
        if probe is not None:
            if not isinstance(probe, dict):
                raise FeatureError(f"Feature {feature_id} has invalid availabilityProbe")
            reject_unknown_fields(probe, probe_fields, f"Feature {feature_id} availabilityProbe")
            probe_type = probe.get("type")
            if probe_type not in {"path", "device-any", "executable", "systemd-unit", "tcp", "http"}:
                raise FeatureError(f"Feature {feature_id} has unsupported availability probe type")
            if probe_type in {"path", "executable"}:
                path = probe.get("path")
                if not isinstance(path, str) or not pathlib.PurePath(path).is_absolute():
                    raise FeatureError(f"Feature {feature_id} availability probe requires an absolute path")
            elif probe_type == "device-any":
                paths = probe.get("paths")
                if (
                    not isinstance(paths, list)
                    or not paths
                    or not all(isinstance(path, str) and pathlib.PurePath(path).is_absolute() for path in paths)
                ):
                    raise FeatureError(f"Feature {feature_id} device probe requires absolute paths")
            elif probe_type == "systemd-unit":
                if not isinstance(probe.get("unit"), str) or not probe["unit"]:
                    raise FeatureError(f"Feature {feature_id} systemd probe requires a unit")
            elif probe_type == "tcp":
                host = probe.get("host", "127.0.0.1")
                port = probe.get("port")
                if host not in {"127.0.0.1", "localhost", "::1"} or not isinstance(port, int) or not 0 < port < 65536:
                    raise FeatureError(f"Feature {feature_id} TCP probe must target a loopback port")
            elif probe_type == "http":
                if not valid_loopback_http_url(probe.get("url")):
                    raise FeatureError(f"Feature {feature_id} HTTP availability probe must be loopback plain HTTP")

    memory_components = catalog.get("memoryComponents", [])
    if not isinstance(memory_components, list):
        raise FeatureError("Feature catalog memoryComponents must be a list")
    for index, component in enumerate(memory_components):
        if not isinstance(component, dict):
            raise FeatureError(f"Memory component {index} is not an object")
        reject_unknown_fields(component, memory_fields, f"Memory component {index}")
        feature = component.get("feature")
        if feature is not None and feature not in features:
            raise FeatureError(f"Memory component {index} references unknown feature {feature}")
        units = component.get("units", [])
        if not isinstance(units, list) or not all(isinstance(unit, str) and unit for unit in units):
            raise FeatureError(f"Memory component {index} has invalid units")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(feature_id: str) -> None:
        if feature_id in visiting:
            raise FeatureError(f"Feature parent cycle includes {feature_id}")
        if feature_id in visited:
            return
        visiting.add(feature_id)
        parent = features[feature_id].get("parent")
        if isinstance(parent, str):
            visit(parent)
        visiting.remove(feature_id)
        visited.add(feature_id)

    for feature_id in features:
        visit(feature_id)
    catalog["schemaVersion"] = 2
    return catalog


def default_state(catalog: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "features": {feature_id: entry_default_mode(entry) for feature_id, entry in catalog["features"].items()},
        "updatedAt": int(time.time()),
    }


def migrate_mode(value: Any, entry: dict[str, Any]) -> str | None:
    allowed = entry_allowed_modes(entry)
    if isinstance(value, str) and value in allowed:
        return value
    if isinstance(value, bool):
        if not value:
            return "off"
        preferred = str(entry.get("legacyTrueMode", "always"))
        if preferred in allowed:
            return preferred
        return "always" if "always" in allowed else entry_default_mode(entry)
    return None


def feature_chain(feature_id: str, features: dict[str, Any]) -> list[str]:
    chain: list[str] = []
    current: str | None = feature_id
    seen: set[str] = set()
    while current is not None:
        if current in seen:
            raise FeatureError(f"Feature parent cycle includes {current}")
        seen.add(current)
        chain.append(current)
        current = features[current].get("parent")
    return list(reversed(chain))


def feature_graph(features: dict[str, Any]) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Build depth and descendant maps in one linear-time pass after validation."""

    children: dict[str, list[str]] = {feature_id: [] for feature_id in features}
    for feature_id, entry in features.items():
        parent = entry.get("parent")
        if isinstance(parent, str):
            children[parent].append(feature_id)

    depths: dict[str, int] = {}

    def depth(feature_id: str) -> int:
        if feature_id in depths:
            return depths[feature_id]
        parent = features[feature_id].get("parent")
        value = 0 if not isinstance(parent, str) else depth(parent) + 1
        depths[feature_id] = value
        return value

    descendants_by_id: dict[str, list[str]] = {}

    def collect(feature_id: str) -> list[str]:
        if feature_id in descendants_by_id:
            return descendants_by_id[feature_id]
        result: list[str] = []
        for child in sorted(children[feature_id]):
            result.append(child)
            result.extend(collect(child))
        descendants_by_id[feature_id] = result
        return result

    for feature_id in features:
        depth(feature_id)
        collect(feature_id)
    return depths, descendants_by_id
