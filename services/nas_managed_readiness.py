#!/usr/bin/env python3
"""Generic readiness probes for Managed Services V2 dependency ordering."""

from __future__ import annotations

import pathlib
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

from nas_managed_resources import ManagedResourceError

READINESS_TYPES = frozenset({"systemd", "tcp", "http", "path"})


def normalize_readiness(service_id: str, value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ManagedResourceError(f"Service {service_id}: readiness must be an object")
    allowed = {"type", "timeoutSeconds", "intervalMilliseconds", "unit", "host", "port", "url", "path"}
    unknown = set(value) - allowed
    if unknown:
        raise ManagedResourceError(f"Service {service_id}: readiness contains unsupported fields {sorted(unknown)}")
    probe_type = value.get("type")
    if probe_type not in READINESS_TYPES:
        raise ManagedResourceError(f"Service {service_id}: unsupported readiness type {probe_type!r}")
    timeout = value.get("timeoutSeconds", 60)
    interval = value.get("intervalMilliseconds", 500)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 1800:
        raise ManagedResourceError(f"Service {service_id}: readiness.timeoutSeconds must be 1..1800")
    if isinstance(interval, bool) or not isinstance(interval, int) or not 50 <= interval <= 10000:
        raise ManagedResourceError(f"Service {service_id}: readiness.intervalMilliseconds must be 50..10000")

    normalized: dict[str, Any] = {
        "type": probe_type,
        "timeoutSeconds": timeout,
        "intervalMilliseconds": interval,
    }
    if probe_type == "systemd":
        unit = value.get("unit")
        if not isinstance(unit, str) or not unit or "/" in unit or ".." in unit:
            raise ManagedResourceError(f"Service {service_id}: systemd readiness requires a valid unit")
        normalized["unit"] = unit
    elif probe_type == "tcp":
        host = value.get("host", "127.0.0.1")
        port = value.get("port")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ManagedResourceError(f"Service {service_id}: TCP readiness host must be loopback")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ManagedResourceError(f"Service {service_id}: TCP readiness requires port 1..65535")
        normalized.update({"host": host, "port": port})
    elif probe_type == "http":
        url = value.get("url")
        if not isinstance(url, str) or not (url.startswith("http://127.0.0.1:") or url.startswith("http://[::1]:") or url.startswith("http://localhost:")):
            raise ManagedResourceError(f"Service {service_id}: HTTP readiness URL must use loopback HTTP")
        normalized["url"] = url
    elif probe_type == "path":
        path = value.get("path")
        if not isinstance(path, str) or not path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
            raise ManagedResourceError(f"Service {service_id}: path readiness requires a safe absolute path")
        normalized["path"] = path
    return normalized


def _ready(probe: dict[str, Any]) -> bool:
    probe_type = probe["type"]
    if probe_type == "systemd":
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", probe["unit"]],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    if probe_type == "tcp":
        try:
            with socket.create_connection((probe["host"], int(probe["port"])), timeout=1):
                return True
        except OSError:
            return False
    if probe_type == "http":
        try:
            request = urllib.request.Request(probe["url"], method="GET", headers={"User-Agent": "nixos-nas-v2/1"})
            with urllib.request.urlopen(request, timeout=2) as response:
                return 200 <= int(response.status) < 500
        except (OSError, urllib.error.URLError, TimeoutError):
            return False
    if probe_type == "path":
        return pathlib.Path(probe["path"]).exists()
    return False


def wait_ready(service_id: str, service: dict[str, Any], *, sleep=time.sleep, monotonic=time.monotonic) -> dict[str, Any]:
    probe = normalize_readiness(service_id, service.get("readiness"))
    if probe is None:
        return {"service": service_id, "ready": True, "probe": None}
    deadline = monotonic() + probe["timeoutSeconds"]
    while True:
        if _ready(probe):
            return {"service": service_id, "ready": True, "probe": probe}
        if monotonic() >= deadline:
            raise ManagedResourceError(
                f"Service {service_id!r} did not become ready within {probe['timeoutSeconds']} seconds"
            )
        sleep(probe["intervalMilliseconds"] / 1000.0)
