#!/usr/bin/env python3
"""Run generic Managed Services V2 readiness probes as a finite oneshot helper."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.parse
from typing import Any


class ReadinessError(RuntimeError):
    """Raised for malformed readiness descriptors or timeout."""


def load_descriptor(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReadinessError(f"unable to read readiness descriptor {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReadinessError("readiness descriptor must be an object")
    return value


def _probe_systemd(probe: dict[str, Any], *, systemctl: str) -> bool:
    unit = probe.get("unit")
    if not isinstance(unit, str) or not unit:
        raise ReadinessError("systemd readiness probe requires a unit")
    try:
        result = subprocess.run(
            [systemctl, "is-active", "--quiet", unit],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _probe_tcp(probe: dict[str, Any]) -> bool:
    host = probe.get("host", "127.0.0.1")
    port = probe.get("port")
    if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
        raise ReadinessError("tcp readiness probe requires string host and integer port")
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _probe_http(probe: dict[str, Any]) -> bool:
    url = probe.get("url")
    minimum = probe.get("acceptStatusMin", 200)
    maximum = probe.get("acceptStatusMax", 399)
    if not isinstance(url, str):
        raise ReadinessError("http readiness probe requires an http(s) URL")
    if not isinstance(minimum, int) or not isinstance(maximum, int):
        raise ReadinessError("http readiness status bounds must be integers")

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ReadinessError("http readiness probe requires an http(s) URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ReadinessError("http readiness URL may not contain credentials or a fragment")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query

    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(parsed.hostname, port, timeout=2)
    try:
        connection.request("GET", target)
        response = connection.getresponse()
        status = response.status
        response.read(4096)
    except (OSError, TimeoutError, http.client.HTTPException):
        return False
    finally:
        connection.close()
    return minimum <= status <= maximum


def _probe_path(probe: dict[str, Any]) -> bool:
    value = probe.get("path")
    if not isinstance(value, str):
        raise ReadinessError("path readiness probe requires a path")
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ReadinessError("readiness path must be absolute and must not contain '..'")
    return os.path.exists(value)


def probe_ready(probe: dict[str, Any], *, systemctl: str) -> bool:
    probe_type = probe.get("type")
    if probe_type == "systemd":
        return _probe_systemd(probe, systemctl=systemctl)
    if probe_type == "tcp":
        return _probe_tcp(probe)
    if probe_type == "http":
        return _probe_http(probe)
    if probe_type == "path":
        return _probe_path(probe)
    raise ReadinessError(f"unsupported readiness probe type {probe_type!r}")


def wait_ready(descriptor: dict[str, Any], *, systemctl: str = "systemctl") -> None:
    timeout = descriptor.get("timeoutSeconds", 60)
    interval_ms = descriptor.get("intervalMilliseconds", 500)
    probes = descriptor.get("probes")
    if not isinstance(timeout, int) or timeout <= 0:
        raise ReadinessError("timeoutSeconds must be a positive integer")
    if not isinstance(interval_ms, int) or interval_ms < 50:
        raise ReadinessError("intervalMilliseconds must be at least 50")
    if not isinstance(probes, list) or not probes or not all(isinstance(probe, dict) for probe in probes):
        raise ReadinessError("readiness descriptor requires a non-empty probes array")

    deadline = time.monotonic() + timeout
    while True:
        if all(probe_ready(probe, systemctl=systemctl) for probe in probes):
            return
        if time.monotonic() >= deadline:
            raise ReadinessError(f"readiness timed out after {timeout} seconds")
        time.sleep(interval_ms / 1000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wait for Managed Services V2 readiness probes")
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--systemctl", default="systemctl")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        wait_ready(load_descriptor(args.config), systemctl=args.systemctl)
    except ReadinessError as exc:
        print(f"nas-v2-readiness: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
