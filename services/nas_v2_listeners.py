#!/usr/bin/env python3
"""Reconcile direct V2 TCP/UDP listener exposure through firewalld."""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

STATE_PATH = pathlib.Path(os.environ.get("NAS_V2_LISTENER_STATE", "/run/nas-control/v2-listeners.json"))
ZONE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class V2ListenerError(RuntimeError):
    pass


def _port_value(exposure: dict[str, Any]) -> str:
    if "port" in exposure:
        return str(int(exposure["port"]))
    start = int(exposure["start"])
    end = int(exposure["end"])
    if end < start:
        raise V2ListenerError("listener port range end precedes start")
    return f"{start}-{end}"


def desired_ports(document: dict[str, Any]) -> list[str]:
    ports: set[str] = set()
    for service_id, service in document.get("services", {}).items():
        if not isinstance(service, dict) or not service.get("enabled"):
            continue
        listeners = service.get("listeners", {})
        if not isinstance(listeners, dict):
            raise V2ListenerError(f"Service {service_id}: listeners must be an object")
        for listener_id, listener in listeners.items():
            if not isinstance(listener, dict) or not listener.get("firewall", True):
                continue
            protocol = listener.get("protocol")
            if protocol not in {"tcp", "udp"}:
                raise V2ListenerError(f"Service {service_id} listener {listener_id}: invalid protocol")
            exposure = listener.get("exposure")
            if not isinstance(exposure, dict):
                raise V2ListenerError(f"Service {service_id} listener {listener_id}: missing exposure")
            ports.add(f"{_port_value(exposure)}/{protocol}")
    return sorted(ports)


def _read_state(path: pathlib.Path = STATE_PATH) -> list[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as exc:
        raise V2ListenerError(f"Unable to read V2 listener state: {exc}") from exc
    ports = value.get("ports") if isinstance(value, dict) else None
    if not isinstance(ports, list) or any(not isinstance(item, str) for item in ports):
        raise V2ListenerError("V2 listener state is invalid")
    return sorted(set(ports))


def _write_state(ports: list[str], path: pathlib.Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"schemaVersion": 1, "ports": ports}, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def reconcile_listeners(
    document: dict[str, Any],
    *,
    zone: str,
    firewall_cmd: str = "firewall-cmd",
    dry_run: bool = False,
) -> dict[str, Any]:
    if ZONE_RE.fullmatch(zone) is None:
        raise V2ListenerError(f"Invalid firewalld zone {zone!r}")
    desired = desired_ports(document)
    previous = _read_state()
    stale = sorted(set(previous) - set(desired))
    plan = {"zone": zone, "ports": desired, "remove": stale}
    if dry_run:
        return plan

    # Reassert every desired port even when the state file is unchanged. A
    # firewalld reload intentionally clears runtime-only rules; services.yaml is
    # the durable authority and reconcile restores them without another DB.
    for port in stale:
        subprocess.run(
            [firewall_cmd, f"--zone={zone}", f"--remove-port={port}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    for port in desired:
        result = subprocess.run(
            [firewall_cmd, f"--zone={zone}", f"--add-port={port}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            # Already-enabled is harmless but other failures must not be hidden.
            query = subprocess.run(
                [firewall_cmd, f"--zone={zone}", f"--query-port={port}"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if query.returncode != 0:
                raise V2ListenerError(f"Unable to expose V2 listener {port}: {result.stderr.strip()}")
    _write_state(desired)
    return plan
