#!/usr/bin/env python3
"""Compile V2 backup resources — now thin wrapper over services.restic/sanoid.

The heavy ZFS/native-dump inventory is owned by NixOS `services.restic`
and `services.sanoid`. This module just emits the direct Restic path list
so `nas_v2_backup_runtime.py` can still do a freshness check before `restic backup`.
"""

from __future__ import annotations

import json
from typing import Any


class BackupProjectionError(RuntimeError):
    pass


def _json_bytes(v: Any) -> bytes:
    return (json.dumps(v, indent=2, sort_keys=True) + "\n").encode()


def compile_backup_projection(effective: dict[str, Any]) -> tuple[bytes, bytes]:
    if effective.get("schemaVersion") != 3:
        raise BackupProjectionError("effective must be schemaVersion 3")
    resources = effective.get("storageResources", {})
    derived = effective.get("derived", {})
    backup_ids = derived.get("backupResources", []) if isinstance(derived, dict) else []
    if not isinstance(resources, dict) or not isinstance(backup_ids, list):
        raise BackupProjectionError("effective missing backup metadata")
    direct: list[str] = []
    inv: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rid in backup_ids:
        if not isinstance(rid, str):
            raise BackupProjectionError("invalid backup id")
        res = resources.get(rid)
        if not isinstance(res, dict):
            raise BackupProjectionError(f"missing backup resource {rid!r}")
        path = res.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise BackupProjectionError(f"invalid backup path {rid!r}")
        if path in seen:
            raise BackupProjectionError(f"duplicate backup path {path!r}")
        seen.add(path)
        # Nix handles `zfs-snapshot`/`native-dump` consistency; we just list filesystem paths.
        direct.append(path)
        inv.append({"id": rid, "path": path, "consistency": "filesystem", "resticSource": path})
    doc = {"schemaVersion": 1, "resources": inv}
    return _json_bytes(doc), "".join(f"{p}\n" for p in sorted(direct)).encode()
