#!/usr/bin/env python3
"""Native Podman network realization for V2 isolated network resources."""

from __future__ import annotations

import json
import subprocess
from typing import Any


class V2PodmanNetworkError(RuntimeError):
    pass


def ensure_network(service_id: str, resolved: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    identity = resolved.get("identity")
    if not isinstance(identity, dict):
        raise V2PodmanNetworkError(f"Service {service_id}: resolvedNetwork.identity is missing")
    name = identity.get("networkName")
    subnet = identity.get("subnet")
    gateway = identity.get("gateway")
    if not all(isinstance(value, str) and value for value in (name, subnet, gateway)):
        raise V2PodmanNetworkError(f"Service {service_id}: resolved Podman network identity is incomplete")
    plan = {"service": service_id, "networkName": name, "subnet": subnet, "gateway": gateway}
    if dry_run:
        return plan

    inspect = subprocess.run(
        ["podman", "network", "inspect", name],
        check=False,
        capture_output=True,
        text=True,
    )
    if inspect.returncode == 0:
        try:
            value = json.loads(inspect.stdout)
            item = value[0] if isinstance(value, list) and value else value
            subnets = item.get("subnets", []) if isinstance(item, dict) else []
            matches = any(
                isinstance(entry, dict)
                and entry.get("subnet") == subnet
                and entry.get("gateway") == gateway
                for entry in subnets
            )
        except (json.JSONDecodeError, TypeError):
            matches = False
        if not matches:
            raise V2PodmanNetworkError(
                f"Service {service_id}: existing Podman network {name!r} does not match V2 subnet/gateway"
            )
        return plan

    subprocess.run(
        [
            "podman",
            "network",
            "create",
            "--driver=bridge",
            "--internal=false",
            f"--subnet={subnet}",
            f"--gateway={gateway}",
            "--opt=isolate=true",
            name,
        ],
        check=True,
    )
    return plan


def remove_network(service_id: str, resolved: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    identity = resolved.get("identity")
    name = identity.get("networkName") if isinstance(identity, dict) else None
    if not isinstance(name, str) or not name:
        raise V2PodmanNetworkError(f"Service {service_id}: resolved network identity is missing")
    if not dry_run:
        subprocess.run(["podman", "network", "rm", name], check=False)
    return {"service": service_id, "networkName": name, "removed": not dry_run}
