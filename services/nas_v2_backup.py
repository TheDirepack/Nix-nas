#!/usr/bin/env python3
"""Compile Managed Services V2 backup resources into native Restic inputs."""

from __future__ import annotations

import json
from typing import Any

import pathlib

from nas_v2_native_dump import NativeDumpProjectionError, resolve_native_dump


class BackupProjectionError(RuntimeError):
    """Raised when a requested backup consistency mode is not safely available."""


def _safe_absolute_path(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or any(character in value for character in ("\x00", "\r", "\n")):
        raise BackupProjectionError(f"{label} is not a safe absolute path")
    candidate = pathlib.PurePosixPath(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise BackupProjectionError(f"{label} is not a safe absolute path")
    return value


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def compile_backup_projection(effective: dict[str, Any]) -> tuple[bytes, bytes]:
    """Return a resource inventory JSON document and direct Restic path list.

    Filesystem-consistent resources can be consumed directly. ZFS snapshot and
    native-dump resources remain in the inventory and are prepared immediately
    before Restic executes by ``nas_v2_backup_runtime.py``.
    """
    if effective.get("schemaVersion") != 3:
        raise BackupProjectionError("compiled effective state must use schema version 3")

    resources = effective.get("storageResources")
    derived = effective.get("derived")
    backup_ids = derived.get("backupResources") if isinstance(derived, dict) else None
    if not isinstance(resources, dict) or not isinstance(backup_ids, list):
        raise BackupProjectionError("compiled effective state is missing backup resource metadata")

    inventory: list[dict[str, Any]] = []
    direct_paths: list[str] = []
    seen_paths: set[str] = set()
    seen_datasets: set[str] = set()
    seen_restic_sources: set[str] = set()

    for resource_id in backup_ids:
        if not isinstance(resource_id, str):
            raise BackupProjectionError("compiled backup resource identity is invalid")
        resource = resources.get(resource_id)
        if not isinstance(resource, dict):
            raise BackupProjectionError(f"compiled backup resource {resource_id!r} is missing")
        path = resource.get("path")
        backup = resource.get("backup")
        if not isinstance(backup, dict):
            raise BackupProjectionError(f"compiled backup resource {resource_id!r} is invalid")
        _safe_absolute_path(path, label=f"compiled backup resource {resource_id!r} path")
        assert isinstance(path, str)
        consistency = backup.get("consistency", "filesystem")
        if consistency not in {"filesystem", "zfs-snapshot", "native-dump", "none"}:
            raise BackupProjectionError(f"backup resource {resource_id!r} has unsupported consistency {consistency!r}")
        if consistency == "zfs-snapshot":
            dataset = resource.get("dataset")
            if not isinstance(dataset, str) or not dataset:
                raise BackupProjectionError(
                    f"backup resource {resource_id!r} requires dataset for zfs-snapshot consistency"
                )
            if dataset in seen_datasets:
                raise BackupProjectionError(f"multiple backup resources share the same dataset {dataset!r}")
            seen_datasets.add(dataset)
        if path in seen_paths:
            raise BackupProjectionError(f"multiple backup resources resolve to the same path {path!r}")
        seen_paths.add(path)

        native_dump: dict[str, str] | None = None
        if consistency == "native-dump":
            try:
                native_dump = resolve_native_dump(effective, resource_id)
            except NativeDumpProjectionError as exc:
                raise BackupProjectionError(str(exc)) from exc

        restic_source: str | None = path if consistency in {"filesystem", "none"} else None
        if restic_source is not None:
            if restic_source in seen_restic_sources:
                raise BackupProjectionError(
                    f"multiple backup resources resolve to the same restic source {restic_source!r}"
                )
            seen_restic_sources.add(restic_source)
            direct_paths.append(restic_source)
        if native_dump is not None:
            artifact_path = native_dump["artifactPath"]
            _safe_absolute_path(artifact_path, label=f"backup resource {resource_id!r} native-dump artifactPath")
            if artifact_path in seen_restic_sources:
                raise BackupProjectionError(
                    f"multiple backup resources resolve to the same restic source {artifact_path!r} (native-dump artifact)"
                )
            if artifact_path in seen_paths:
                raise BackupProjectionError(
                    f"native-dump artifact path {artifact_path!r} collides with backup resource path"
                )
            seen_restic_sources.add(artifact_path)
        entry: dict[str, Any] = {
            "id": resource_id,
            "path": path,
            "dataset": resource.get("dataset"),
            "scope": resource.get("scope", "system"),
            "stateClass": resource.get("stateClass"),
            "consistency": consistency,
            "resticSource": restic_source,
        }
        if native_dump is not None:
            entry["nativeDump"] = native_dump
        inventory.append(entry)

    document = {
        "schemaVersion": 1,
        "resources": inventory,
    }
    path_list = "".join(f"{path}\n" for path in sorted(direct_paths)).encode("utf-8")
    return _json_bytes(document), path_list


__all__ = ["BackupProjectionError", "compile_backup_projection"]
