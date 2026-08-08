#!/usr/bin/env python3
"""Podman Compose runtime adapter for managed-services."""
from __future__ import annotations
import pathlib, subprocess
from typing import Any
from nas_managed_service import ManagedServiceError
def plan_compose(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "compose":
        return {"actions": [], "warnings": [f"Service {service_id} is not a Compose service"]}
    source = runtime.get("source", "")
    if not source.startswith(f"/var/lib/nas-control/apps/{service_id}/"):
        raise ManagedServiceError(f"Compose source for {service_id} must be under /var/lib/nas-control/apps/{service_id}/")
    if not source.endswith((".yaml", ".yml", "compose.yaml")):
        raise ManagedServiceError(f"Compose source for {service_id} must be a YAML file")
    return {"service": service_id, "runtime": "compose", "actions": [{"type": "compose", "project": service_id, "source": source}]}
def apply_compose(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_compose(service_id, service)
    if dry_run:
        return plan
    for action in plan["actions"]:
        compose_file = pathlib.Path(action["source"])
        if not compose_file.exists():
            raise ManagedServiceError(f"Compose file not found: {compose_file}")
        subprocess.run(["podman", "compose", "-f", str(compose_file), "up", "-d"], check=False, env={"COMPOSE_PROJECT_NAME": service_id})
    return plan
def remove_compose(service_id: str, *, dry_run: bool = False) -> None:
    if dry_run:
        return
    subprocess.run(["podman", "compose", "-p", service_id, "down", "--remove-orphans"], check=False)
