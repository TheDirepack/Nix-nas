#!/usr/bin/env python3
"""Thin Podman Compose adapter for managed services."""
from __future__ import annotations

import pathlib
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError


def _compose_source(service_id: str, service: dict[str, Any]) -> pathlib.Path:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "compose":
        raise ManagedServiceError(f"Service {service_id} is not a Compose service")

    source = runtime.get("source", "")
    root = pathlib.PurePosixPath(f"/var/lib/nas-control/apps/{service_id}")
    path = pathlib.PurePosixPath(source)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ManagedServiceError(
            f"Compose source for {service_id} must be under {root}/"
        ) from exc
    if path.suffix not in {".yaml", ".yml"}:
        raise ManagedServiceError(f"Compose source for {service_id} must be a YAML file")
    return pathlib.Path(str(path))


def plan_compose(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "compose":
        return {
            "actions": [],
            "warnings": [f"Service {service_id} is not a Compose service"],
        }

    source = _compose_source(service_id, service)
    enabled = bool(service.get("enabled"))
    return {
        "service": service_id,
        "runtime": "podman-compose",
        "source": str(source),
        "project": service_id,
        "enabled": enabled,
        "actions": [
            {
                "type": "podman-compose",
                "operation": "up" if enabled else "down",
                "project": service_id,
                "source": str(source),
            }
        ],
    }


def apply_compose(
    service_id: str, service: dict[str, Any], *, dry_run: bool = False
) -> dict[str, Any]:
    plan = plan_compose(service_id, service)
    if dry_run or not plan["actions"]:
        return plan

    command = [
        "podman",
        "compose",
        "-p",
        plan["project"],
        "-f",
        plan["source"],
    ]
    if plan["enabled"]:
        command.extend(["up", "-d"])
    else:
        command.extend(["down", "--remove-orphans"])
    subprocess.run(command, check=True)
    return plan


def remove_compose(service_id: str, *, dry_run: bool = False) -> None:
    if dry_run:
        return
    subprocess.run(
        ["podman", "compose", "-p", service_id, "down", "--remove-orphans"],
        check=True,
    )
