#!/usr/bin/env python3
"""Thin Podman Quadlet adapter for managed services.

Nix-nas owns NAS-specific policy and metadata. Podman owns Quadlet parsing,
installation, replacement, systemd reloads, and removal.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError

APP_ROOT = pathlib.Path("/var/lib/nas-control/apps")
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.service$")


def _quadlet_source(service_id: str, service: dict[str, Any]) -> pathlib.Path:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "quadlet":
        raise ManagedServiceError(f"Service {service_id} is not a Quadlet service")

    source = runtime.get("source", "")
    if not isinstance(source, str) or not pathlib.PurePosixPath(source).is_absolute():
        raise ManagedServiceError(f"Podman source for {service_id} must be under {APP_ROOT / service_id}/")
    app_root = APP_ROOT.resolve()
    root = (app_root / service_id).resolve()
    path = pathlib.Path(source).resolve()
    try:
        root.relative_to(app_root)
        path.relative_to(root)
    except ValueError as exc:
        raise ManagedServiceError(f"Podman source for {service_id} must be under {root}/") from exc

    if path.suffix != ".container":
        raise ManagedServiceError(f"Podman source for {service_id} must be a native .container Quadlet file")
    return path


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


def apply_podman(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
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
    listed = subprocess.run(
        [
            "podman",
            "quadlet",
            "list",
            "--filter",
            f"name={pathlib.Path(plan['source']).name}",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        rows = json.loads(listed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ManagedServiceError(f"Podman returned invalid Quadlet metadata for {service_id}") from exc
    source_name = pathlib.Path(plan["source"]).name
    units: list[str] = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict) or row.get("Name") != source_name or row.get("App") != service_id:
                continue
            unit = row.get("UnitName")
            if isinstance(unit, str):
                units.append(unit)
    if len(units) != 1 or not UNIT_RE.fullmatch(units[0]):
        raise ManagedServiceError(f"Podman did not report one valid unit for {service_id}")
    plan["unit"] = units[0]
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
