#!/usr/bin/env python3
"""Managed Services V2 backup inventory and consistency executor.

Restic remains the repository engine and systemd remains the scheduler. This
module removes duplicated path authority by deriving dynamic backup inputs from
V2 storage resources. It creates only short-lived, exact-name ZFS snapshots for
resources that explicitly request snapshot consistency; no custom archive
format or resident backup daemon is introduced.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any

from nas_managed_resources import ManagedResourceError, validate_storage_resources

DEFAULT_EFFECTIVE = pathlib.Path(os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json"))
DEFAULT_STATE = pathlib.Path(os.environ.get("NAS_BACKUP_V2_STATE", "/run/nas-backup-v2/snapshots.json"))
SNAPSHOT_PREFIX = "nixos-nas-v2-backup"
DATASET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
SNAPSHOT_RE = re.compile(rf"^[A-Za-z0-9][A-Za-z0-9_.:/-]*@{SNAPSHOT_PREFIX}-\d{{8}}T\d{{6}}Z$")


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
    elif consistency == "filesystem":
        pass
    elif consistency in {"postgres", "native"}:
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
    grouped: dict[str, list[dict[str, Any]]] = {"zfs-snapshot": [], "filesystem": [], "postgres": [], "native": []}
    resources_out: list[dict[str, Any]] = []
    for resource_id in sorted(selected):
        resource = resources.get(resource_id)
        if resource is None:
            raise BackupPlanError(f"Backup resource {resource_id!r} does not exist")
        item = _resource_plan(resource_id, resource, snap)
        grouped[item["consistency"]].append(item)
        resources_out.append(item)
    return {"schemaVersion": 1, "snapshotName": snap, "resources": resources_out, "groups": grouped}


def dynamic_files(plan: dict[str, Any], *, include_snapshots: bool = False) -> list[str]:
    files: list[str] = []
    for item in plan.get("groups", {}).get("filesystem", []):
        path = item.get("path")
        if isinstance(path, str) and path.startswith("/"):
            files.append(path)
    if include_snapshots:
        for item in plan.get("groups", {}).get("zfs-snapshot", []):
            path = item.get("snapshotPath")
            if isinstance(path, str) and path.startswith("/"):
                files.append(path)
    return sorted(set(files))


def _atomic_write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _dataset_mountpoint(dataset: str) -> pathlib.Path:
    result = subprocess.run(
        ["zfs", "get", "-H", "-o", "value", "mountpoint", dataset],
        check=True,
        capture_output=True,
        text=True,
    )
    raw = result.stdout.strip()
    if not raw.startswith("/") or raw in {"none", "legacy"}:
        raise BackupPlanError(f"ZFS dataset {dataset!r} has no usable filesystem mountpoint")
    mountpoint = pathlib.Path(raw)
    if ".." in pathlib.PurePosixPath(raw).parts:
        raise BackupPlanError(f"ZFS dataset {dataset!r} returned an unsafe mountpoint")
    return mountpoint


def _snapshot_resource_path(item: dict[str, Any], snapshot_name_value: str) -> pathlib.Path:
    dataset = item["dataset"]
    mountpoint = _dataset_mountpoint(dataset)
    resource_path = pathlib.Path(item["path"])
    try:
        relative = resource_path.relative_to(mountpoint)
    except ValueError as exc:
        raise BackupPlanError(
            f"Resource {item['resource']!r} path {resource_path} is not beneath dataset {dataset!r} mountpoint {mountpoint}"
        ) from exc
    snapshot_root = mountpoint / ".zfs" / "snapshot" / snapshot_name_value
    return snapshot_root if str(relative) == "." else snapshot_root / relative


def _destroy_snapshot(snapshot: str) -> None:
    if SNAPSHOT_RE.fullmatch(snapshot) is None:
        raise BackupPlanError(f"Refusing to destroy snapshot outside V2 backup namespace: {snapshot!r}")
    subprocess.run(["zfs", "destroy", snapshot], check=True)


def cleanup_snapshots(state_path: pathlib.Path = DEFAULT_STATE) -> list[str]:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupPlanError(f"Unable to read snapshot cleanup state: {exc}") from exc
    snapshots = state.get("snapshots")
    if state.get("schemaVersion") != 1 or not isinstance(snapshots, list) or any(not isinstance(item, str) for item in snapshots):
        raise BackupPlanError("Snapshot cleanup state is invalid")
    destroyed: list[str] = []
    for snapshot in snapshots:
        _destroy_snapshot(snapshot)
        destroyed.append(snapshot)
    state_path.unlink(missing_ok=True)
    return destroyed


def prepare_files(
    effective: dict[str, Any],
    *,
    timestamp: dt.datetime | None = None,
    state_path: pathlib.Path = DEFAULT_STATE,
) -> list[str]:
    plan = build_backup_plan(effective, timestamp=timestamp)
    if state_path.exists():
        raise BackupPlanError(f"Previous V2 backup snapshot state still exists: {state_path}")

    created: list[str] = []
    snapshot_by_dataset: dict[str, str] = {}
    try:
        # Multiple resources may be subdirectories of one dataset. Create one
        # atomic snapshot per dataset and reuse its read-only view for each
        # selected resource rather than attempting duplicate same-name snapshots.
        for item in plan["groups"]["zfs-snapshot"]:
            dataset = item["dataset"]
            snapshot = item["snapshot"]
            if SNAPSHOT_RE.fullmatch(snapshot) is None:
                raise BackupPlanError(f"Generated snapshot name is invalid: {snapshot!r}")
            prior = snapshot_by_dataset.get(dataset)
            if prior is None:
                subprocess.run(["zfs", "snapshot", snapshot], check=True)
                snapshot_by_dataset[dataset] = snapshot
                created.append(snapshot)
            elif prior != snapshot:
                raise BackupPlanError(f"Dataset {dataset!r} resolved to inconsistent snapshot names")

        for item in plan["groups"]["zfs-snapshot"]:
            snapshot_path = _snapshot_resource_path(item, plan["snapshotName"])
            item["snapshotPath"] = str(snapshot_path)
            if not snapshot_path.is_dir():
                raise BackupPlanError(
                    f"ZFS snapshot {item['snapshot']!r} was created but resource {item['resource']!r} view is unavailable at {snapshot_path}"
                )

        if created:
            _atomic_write_json(state_path, {"schemaVersion": 1, "snapshots": created})
        return dynamic_files(plan, include_snapshots=True)
    except Exception:
        for snapshot in reversed(created):
            try:
                _destroy_snapshot(snapshot)
            except Exception:
                pass
        state_path.unlink(missing_ok=True)
        raise


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
    parser.add_argument("command", choices=["plan", "files", "prepare-files", "cleanup"])
    parser.add_argument("--effective", type=pathlib.Path, default=DEFAULT_EFFECTIVE)
    parser.add_argument("--state", type=pathlib.Path, default=DEFAULT_STATE)
    args = parser.parse_args(argv)
    try:
        if args.command == "cleanup":
            for snapshot in cleanup_snapshots(args.state):
                print(snapshot)
            return 0
        effective = load_effective(args.effective)
        plan = build_backup_plan(effective)
        if args.command == "files":
            files = dynamic_files(plan)
        elif args.command == "prepare-files":
            files = prepare_files(effective, state_path=args.state)
        else:
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        for path in files:
            print(path)
        return 0
    except (BackupPlanError, subprocess.CalledProcessError) as exc:
        print(f"nas-backup-v2: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
