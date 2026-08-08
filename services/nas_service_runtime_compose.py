#!/usr/bin/env python3
"""Podman Compose runtime adapter for managed-services."""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
from typing import Any

from nas_managed_service import ManagedServiceError

_DANGEROUS_PATTERNS = (
    (re.compile(r"(?m)^\s*privileged\s*:\s*true\s*(?:#.*)?$", re.IGNORECASE), "privileged containers"),
    (re.compile(r"(?m)^\s*network_mode\s*:\s*[\"']?host[\"']?\s*(?:#.*)?$", re.IGNORECASE), "host networking"),
    (re.compile(r"(?m)^\s*pid\s*:\s*[\"']?host[\"']?\s*(?:#.*)?$", re.IGNORECASE), "host PID namespace"),
    (re.compile(r"(?m)^\s*ipc\s*:\s*[\"']?host[\"']?\s*(?:#.*)?$", re.IGNORECASE), "host IPC namespace"),
    (re.compile(r"/(?:run/)?podman/podman\.sock|/var/run/docker\.sock", re.IGNORECASE), "container-engine socket mounts"),
)


def _provider() -> str:
    provider = os.environ.get("PODMAN_COMPOSE_PROVIDER") or shutil.which("podman-compose")
    if not provider:
        raise ManagedServiceError("podman-compose is required but was not found")
    return provider


def _scan_compose(path: pathlib.Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManagedServiceError(f"Unable to read Compose file {path}: {exc}") from exc
    warnings: list[str] = []
    for pattern, label in _DANGEROUS_PATTERNS:
        if pattern.search(text):
            warnings.append(label)
    if re.search(r"(?m)^\s*-\s*/\s*:\s*[^\s]+", text):
        warnings.append("host root filesystem mounts")
    return warnings


def plan_compose(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") != "compose":
        return {"actions": [], "warnings": [f"Service {service_id} is not a Compose service"]}
    source = runtime.get("source", "")
    if not source.startswith(f"/var/lib/nas-control/apps/{service_id}/"):
        raise ManagedServiceError(
            f"Compose source for {service_id} must be under /var/lib/nas-control/apps/{service_id}/"
        )
    if not source.endswith((".yaml", ".yml")):
        raise ManagedServiceError(f"Compose source for {service_id} must be a YAML file")
    compose_file = pathlib.Path(source)
    warnings = _scan_compose(compose_file) if compose_file.exists() else []
    if warnings and os.environ.get("NAS_ALLOW_UNSAFE_COMPOSE") != "1":
        raise ManagedServiceError(
            "Compose file requests dangerous host integration: " + ", ".join(sorted(set(warnings)))
        )
    return {
        "service": service_id,
        "runtime": "compose",
        "actions": [{"type": "compose", "project": service_id, "source": source}],
        "warnings": warnings,
    }


def apply_compose(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_compose(service_id, service)
    if dry_run:
        return plan
    provider = _provider()
    for action in plan["actions"]:
        compose_file = pathlib.Path(action["source"])
        if not compose_file.exists():
            raise ManagedServiceError(f"Compose file not found: {compose_file}")
        env = dict(os.environ)
        env["COMPOSE_PROJECT_NAME"] = service_id
        subprocess.run([provider, "-f", str(compose_file), "up", "-d"], check=True, env=env)
    return plan


def remove_compose(service_id: str, *, dry_run: bool = False) -> None:
    if dry_run:
        return
    provider = _provider()
    subprocess.run([provider, "-p", service_id, "down", "--remove-orphans"], check=True, env=dict(os.environ))
