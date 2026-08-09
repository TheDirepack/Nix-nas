#!/usr/bin/env python3
"""Managed Services V2 backup inventory and consistency planner.

Restic remains the repository engine and systemd remains the scheduler. This
module removes duplicated path authority by deriving dynamic backup inputs from
V2 storage resources. It does not create another archive format or daemon.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import sys
from typing import Any

from nas_managed_resources import ManagedResourceError, validate_storage_resources

DEFAULT_EFFECTIVE = pathlib.Path(
    os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json")
)
SNAPSHOT_PREFIX = "nixos-nas-v2-backup"
DATASET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")


class BackupPlanError(RuntimeError):
    pass


def snapshot_name(timestamp: dt.datetime | None = None) -> str:
    current = timestamp or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    current = current.astimezone(dt.timezone.utc)
    return f"{SNAPSHOT_PREFIX}-{current:%Y%m%dT%H%M%SZ}"


def _resource_plan(resource_id: str, resource: dict[str, Any], snapshot: str) -> dict[str, Any]:
    backup = resource["backup"]
    consistency = backup["consistency"]
    if not backup["enabled"]:
        raise BackupPlanError(f"Resource {resource_id!r} is not enabled for backup")
    if resource["stateClass"] in {"cache", "ephemeral"}:
        raise BackupPlanError(f"Resource {resource_id!r} has non-authoritative state class {resource['stateClass']!r}")

    result: dict[str, Any] = {
        "resource": resource_id,
        "path": resource["path"],
        "scope": resource["scope"],
        "stateClass": resource["stateClass"],
        "consistency": consistency,
    }
    if resource.get("pathTemplate"):
        result["pathTemplate"] = resource["pathTemplate"]

    if consistency == "zfs-snapshot":
        dataset = resource.get("dataset")
        if not isinstance(dataset, str) or DATASET_RE.fullmatch(dataset) is None:
            raise BackupPlanError(f"Resource {resource_id!r}: zfs-snapshot consistency requires a valid dataset")
        result["dataset"] = dataset
        result["snapshot"] = f"{dataset}@{snapshot}"
        # ZFS snapshots are normally visible beneath the dataset mount at
        # .zfs/snapshot/<name>. The executor verifies snapdir/access before
        # handing this path to Restic; the planner never assumes it exists.
        result["snapshotRelative"] = f".zfs/snapshot/{snapshot}"
    elif consistency == "filesystem":
        pass
    elif consistency in {"postgres", "native"}:
        # These require a named native dump/hook rather than backing a live
        # application data directory. The executor/staging layer owns the hook.
        result["requiresNativeStage"] = True
    else:
        raise BackupPlanError(f"Resource {resource_id!r}: unsupported backup consistency {consistency!r}")
    return result


def build_backup_plan(effective: dict[str, Any], *, timestamp: dt.datetime | None = None) -> dict[str, Any]:
    try:
        resources = validate_storage_resources(effective.get("storageResources"))
    except ManagedResourceError as exc:
        raise BackupPlanError(str(exc)) from exc
    selected = effective.get("backupResources")
    if selected is None:
        selected = sorted(resource_id for resource_id, resource in resources.items() if resource["backup"]["enabled"])
    if not isinstance(selected, list) or any(not isinstance(item, str) for item in selected):
        raise BackupPlanError("effective backupResources must be an array of resource IDs")
    if len(selected) != len(set(selected)):
        raise BackupPlanError("effective backupResources contains duplicates")

    snap = snapshot_name(timestamp)
    grouped: dict[str, list[dict[str, Any]]] = {
        "zfs-snapshot": [],
        "filesystem": [],
        "postgres": [],
        "native": [],
    }
    resources_out: list[dict[str, Any]] = []
    for resource_id in sorted(selected):
        resource = resources.get(resource_id)
        if resource is None:
            raise BackupPlanError(f"Backup resource {resource_id!r} does not exist")
        item = _resource_plan(resource_id, resource, snap)
        grouped[item["consistency"]].append(item)
        resources_out.append(item)

    return {
        "schemaVersion": 1,
        "snapshotName": snap,
        "resources": resources_out,
        "groups": grouped,
    }


def load_effective(path: pathlib.Path = DEFAULT_EFFECTIVE) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BackupPlanError(f"Effective V2 registry is missing: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupPlanError(f"Unable to read effective V2 registry: {exc}") from exc
    if not isinstance(value, dict):
        raise BackupPlanError("Effective V2 registry must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nas-backup-v2")
    parser.add_argument("command", choices=["plan"])
    parser.add_argument("--effective", type=pathlib.Path, default=DEFAULT_EFFECTIVE)
    args = parser.parse_args(argv)
    try:
        plan = build_backup_plan(load_effective(args.effective))
    except BackupPlanError as exc:
        print(f"nas-backup-v2: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
