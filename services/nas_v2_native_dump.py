#!/usr/bin/env python3
"""Resolve generic native-dump backup graphs from Managed Services V2 state.

No application names are recognized here. A native-dump source is an
authoritative storage resource with backup consistency ``native-dump``. Exactly
one enabled managed V2 job reads that source and writes exactly one
``stateClass: derived`` storage resource. The job's systemd owner becomes the
synchronous preparation unit and the derived resource path becomes Restic's
source.
"""

from __future__ import annotations

import pathlib
from typing import Any


class NativeDumpProjectionError(RuntimeError):
    """Raised when a native-dump graph is ambiguous or unsafe."""


def _absolute_path(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or any(character in value for character in ("\x00", "\r", "\n")):
        raise NativeDumpProjectionError(f"{label} is not a safe absolute path")
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise NativeDumpProjectionError(f"{label} is not a safe absolute path")
    return value


def _runtime_owner(effective: dict[str, Any], service_id: str) -> str:
    derived = effective.get("derived")
    runtimes = derived.get("runtime") if isinstance(derived, dict) else None
    runtime = runtimes.get(service_id) if isinstance(runtimes, dict) else None
    owner = runtime.get("ownerUnit") if isinstance(runtime, dict) else None
    if not isinstance(owner, str) or not owner.endswith(".service"):
        raise NativeDumpProjectionError(
            f"native-dump preparation job {service_id!r} is missing a concrete systemd owner unit"
        )
    return owner


def resolve_native_dump(effective: dict[str, Any], source_id: str) -> dict[str, str]:
    resources = effective.get("storageResources")
    services = effective.get("services")
    if not isinstance(resources, dict) or not isinstance(services, dict):
        raise NativeDumpProjectionError("compiled effective state is missing services or storageResources")
    source = resources.get(source_id)
    if not isinstance(source, dict):
        raise NativeDumpProjectionError(f"native-dump source resource {source_id!r} is missing")
    backup = source.get("backup")
    if not isinstance(backup, dict) or backup.get("enabled") is not True or backup.get("consistency") != "native-dump":
        raise NativeDumpProjectionError(f"storage resource {source_id!r} is not an enabled native-dump source")
    if source.get("stateClass") != "authoritative":
        raise NativeDumpProjectionError(f"native-dump source resource {source_id!r} must be authoritative")
    _absolute_path(source.get("path"), label=f"native-dump source {source_id!r} path")

    candidates: list[tuple[str, str]] = []
    malformed: list[str] = []
    for service_id in sorted(services):
        service = services[service_id]
        if (
            not isinstance(service, dict)
            or service.get("managed", True) is not True
            or service.get("enabled", True) is not True
        ):
            continue
        workload = service.get("workload")
        storage = service.get("storage")
        if not isinstance(storage, list):
            continue
        reads_source = any(
            isinstance(attachment, dict)
            and attachment.get("resource") == source_id
            and attachment.get("access", "read") == "read"
            for attachment in storage
        )
        if not reads_source:
            continue
        if not isinstance(workload, dict) or workload.get("kind") != "job":
            malformed.append(f"{service_id}: a service reading the native-dump source is not a job")
            continue

        artifact_ids: list[str] = []
        for attachment in storage:
            if not isinstance(attachment, dict) or attachment.get("access", "read") != "write":
                continue
            artifact_id = attachment.get("resource")
            if not isinstance(artifact_id, str):
                continue
            artifact = resources.get(artifact_id)
            if isinstance(artifact, dict) and artifact.get("stateClass") == "derived":
                artifact_ids.append(artifact_id)
        artifact_ids = sorted(set(artifact_ids))
        if len(artifact_ids) != 1:
            malformed.append(
                f"{service_id}: expected exactly one writable derived artifact resource, found {len(artifact_ids)}"
            )
            continue
        candidates.append((service_id, artifact_ids[0]))

    if len(candidates) != 1:
        detail = "; ".join(malformed)
        suffix = f" ({detail})" if detail else ""
        raise NativeDumpProjectionError(
            f"native-dump source {source_id!r} requires exactly one enabled managed preparation job; found {len(candidates)}{suffix}"
        )

    service_id, artifact_id = candidates[0]
    artifact = resources[artifact_id]
    if artifact.get("scope", "system") != "system":
        raise NativeDumpProjectionError(
            f"native-dump artifact resource {artifact_id!r} must use system scope so Restic has one deterministic path"
        )
    artifact_backup = artifact.get("backup")
    if isinstance(artifact_backup, dict) and artifact_backup.get("enabled") is True:
        raise NativeDumpProjectionError(
            f"native-dump artifact resource {artifact_id!r} must not be independently backup-enabled"
        )
    artifact_path = _absolute_path(
        artifact.get("path"),
        label=f"native-dump artifact {artifact_id!r} path",
    )
    if artifact_path == source.get("path"):
        raise NativeDumpProjectionError("native-dump artifact path must differ from its authoritative source path")

    return {
        "preparationService": service_id,
        "preparationUnit": _runtime_owner(effective, service_id),
        "artifactResource": artifact_id,
        "artifactPath": artifact_path,
    }


__all__ = ["NativeDumpProjectionError", "resolve_native_dump"]
