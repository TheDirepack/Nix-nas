#!/usr/bin/env python3
"""Thin Podman Quadlet adapter for managed services.

Nix-nas owns NAS-specific policy and metadata. Podman owns Quadlet parsing,
installation, replacement, systemd reloads, and removal.
"""
from __future__ import annotations

import pathlib
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError


def _quadlet_source(service_id: str, service: dict[str, Any]) -> pathlib.Path:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "quadlet":
        raise ManagedServiceError(f"Service {service_id} is not a Quadlet service")

    source = runtime.get("source", "")
    root = pathlib.PurePosixPath(f"/var/lib/nas-control/apps/{service_id}")
    path = pathlib.PurePosixPath(source)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ManagedServiceError(
            f"Podman source for {service_id} must be under {root}/"
        ) from exc

    if path.suffix != ".container":
        raise ManagedServiceError(
            f"Podman source for {service_id} must be a native .container Quadlet file"
        )
    return pathlib.Path(str(path))


def plan_podman(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "quadlet":
        return {
            "actions": [],
            "warnings": [f"Service {service_id} is not a Quadlet service"],
        }

    source = _quadlet_source(service_id, service)
    unit = f"{source.stem}.service"
    return {
        "service": service_id,
        "runtime": "podman-quadlet",
        "source": str(source),
        "application": service_id,
        "unit": unit,
        "enabled": bool(service.get("enabled")),
        "actions": [
            {
                "type": "podman-quadlet-install",
                "source": str(source),
                "application": service_id,
                "replace": True,
            },
            {
                "type": "systemd-unit",
                "unit": unit,
                "operation": "restart" if service.get("enabled") else "stop",
            },
        ],
    }


def apply_podman(
    service_id: str, service: dict[str, Any], *, dry_run: bool = False
) -> dict[str, Any]:
    plan = plan_podman(service_id, service)
    if dry_run or not plan["actions"]:
        return plan

    subprocess.run(
        [
            "podman",
            "quadlet",
            "install",
            "--replace",
            f"--application={plan['application']}",
            plan["source"],
        ],
        check=True,
    )
    operation = "restart" if plan["enabled"] else "stop"
    subprocess.run(["systemctl", operation, plan["unit"]], check=True)
    return plan


def remove_podman(service_id: str, *, dry_run: bool = False) -> None:
    if dry_run:
        return
    subprocess.run(
        [
            "podman",
            "quadlet",
            "rm",
            "--force",
            "--ignore",
            "--recursive",
            service_id,
        ],
        check=True,
    )
