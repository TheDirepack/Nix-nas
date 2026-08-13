#!/usr/bin/env python3
"""Prepare and clean native Managed Services V2 backup resources."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

from nas_v2_backup import BackupProjectionError as _BackupProjectionError
from nas_v2_backup import _safe_absolute_path as _shared_safe_path


class BackupRuntimeError(RuntimeError):
    """Raised when a native backup consistency operation cannot be completed safely."""


def _load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BackupRuntimeError(f"{path} must contain a JSON object")
    return value


def _write_atomic(path: pathlib.Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = pathlib.Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _safe_absolute_path(value: Any, *, label: str) -> str:
    try:
        return _shared_safe_path(value, label=label)
    except _BackupProjectionError:
        raise BackupRuntimeError(f"{label} is not a safe absolute path") from None


def _run(argv: list[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        raise BackupRuntimeError(f"native backup command failed: {detail}")
    return result.stdout.strip()


def _native_dump_path(resource_id: str, resource: dict[str, Any], *, systemctl_bin: str) -> tuple[str, dict[str, str]]:
    native_dump = resource.get("nativeDump")
    if not isinstance(native_dump, dict):
        raise BackupRuntimeError(f"backup resource {resource_id!r} is missing its compiled native-dump job mapping")
    preparation_unit = native_dump.get("preparationUnit")
    preparation_service = native_dump.get("preparationService")
    artifact_resource = native_dump.get("artifactResource")
    artifact_path = native_dump.get("artifactPath")
    if (
        not isinstance(preparation_unit, str)
        or not preparation_unit.endswith(".service")
        or not isinstance(preparation_service, str)
        or not isinstance(artifact_resource, str)
        or not isinstance(artifact_path, str)
        or not pathlib.PurePosixPath(artifact_path).is_absolute()
        or ".." in pathlib.PurePosixPath(artifact_path).parts
    ):
        raise BackupRuntimeError(f"backup resource {resource_id!r} has an invalid compiled native-dump job mapping")
    artifact = pathlib.Path(artifact_path)
    try:
        artifact.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(artifact, 0o700)
    except OSError as exc:
        raise BackupRuntimeError(f"unable to prepare native-dump artifact directory {artifact_path!r}: {exc}") from exc
    if not artifact.is_dir():
        raise BackupRuntimeError(f"native-dump artifact resource {artifact_resource!r} must resolve to a directory")
    try:
        mode = artifact.stat().st_mode & 0o777
        if mode != 0o700:
            os.chmod(artifact, 0o700)
            mode = artifact.stat().st_mode & 0o777
            if mode != 0o700:
                raise BackupRuntimeError(
                    f"native-dump artifact directory {artifact_path!r} has unsafe mode {oct(mode)}"
                )
    except OSError as exc:
        raise BackupRuntimeError(
            f"unable to enforce native-dump artifact directory mode {artifact_path!r}: {exc}"
        ) from exc
    try:
        for child in list(artifact.iterdir()):
            try:
                if child.is_symlink() or child.is_file():
                    child.unlink()
                elif child.is_dir():
                    shutil.rmtree(child)
            except OSError as exc:
                raise BackupRuntimeError(f"unable to clean stale native-dump artifact {child!r}: {exc}") from exc
    except OSError as exc:
        raise BackupRuntimeError(f"unable to inspect native-dump artifact directory {artifact_path!r}: {exc}") from exc
    _run([systemctl_bin, "restart", preparation_unit])
    try:
        produced = any(artifact.iterdir())
    except OSError as exc:
        raise BackupRuntimeError(f"unable to inspect native-dump artifact directory {artifact_path!r}: {exc}") from exc
    if not produced:
        raise BackupRuntimeError(
            f"native-dump preparation job {preparation_service!r} completed without producing data in {artifact_path!r}"
        )
    return artifact_path, {
        "source": resource_id,
        "preparationService": preparation_service,
        "preparationUnit": preparation_unit,
        "artifactResource": artifact_resource,
        "artifactPath": artifact_path,
    }


def prepare(
    *,
    inventory_path: pathlib.Path,
    paths_path: pathlib.Path,
    state_path: pathlib.Path,
    zfs_bin: str,
    systemctl_bin: str,
) -> dict[str, Any]:
    inventory = _load_json(inventory_path)
    if inventory.get("schemaVersion") != 1 or not isinstance(inventory.get("resources"), list):
        raise BackupRuntimeError("compiled V2 backup inventory has an unsupported schema")
    runtime_paths: list[str] = []
    snapshots: list[dict[str, str]] = []
    native_dumps: list[dict[str, str]] = []
    snapshots_by_dataset: dict[str, tuple[str, str]] = {}
    dataset_mountpoints: dict[str, str] = {}

    def _persist_state() -> None:
        state = {"schemaVersion": 1, "snapshots": list(snapshots), "nativeDumps": list(native_dumps)}
        _write_atomic(state_path, (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"), 0o600)

    try:
        for resource in inventory["resources"]:
            if not isinstance(resource, dict):
                raise BackupRuntimeError("compiled V2 backup inventory contains an invalid resource")
            resource_id = resource.get("id")
            path = resource.get("path")
            consistency = resource.get("consistency")
            if not isinstance(resource_id, str):
                raise BackupRuntimeError("compiled V2 backup inventory contains an invalid resource id")
            _safe_absolute_path(path, label=f"backup resource {resource_id!r} path")
            assert isinstance(path, str)
            if consistency in {"filesystem", "none"}:
                runtime_paths.append(path)
                continue
            if consistency == "native-dump":
                artifact_path, prepared = _native_dump_path(resource_id, resource, systemctl_bin=systemctl_bin)
                _safe_absolute_path(artifact_path, label=f"backup resource {resource_id!r} native-dump artifactPath")
                runtime_paths.append(artifact_path)
                native_dumps.append(prepared)
                _persist_state()
                continue
            if consistency != "zfs-snapshot":
                raise BackupRuntimeError(f"backup resource {resource_id!r} has unsupported consistency {consistency!r}")
            dataset = resource.get("dataset")
            if not isinstance(dataset, str) or not dataset:
                raise BackupRuntimeError(
                    f"backup resource {resource_id!r} requires dataset for zfs-snapshot consistency"
                )
            mountpoint = dataset_mountpoints.get(dataset)
            if mountpoint is None:
                mountpoint = _run([zfs_bin, "get", "-H", "-o", "value", "mountpoint", dataset])
                dataset_mountpoints[dataset] = mountpoint
            if mountpoint != path:
                raise BackupRuntimeError(
                    f"backup resource {resource_id!r} path {path!r} does not match ZFS dataset {dataset!r} mountpoint {mountpoint!r}"
                )
            current = snapshots_by_dataset.get(dataset)
            if current is None:
                name = f"nas-v2-restic-{time.time_ns()}-{os.getpid()}"
                _run([zfs_bin, "snapshot", f"{dataset}@{name}"])
                snapshot_path = str(pathlib.PurePosixPath(path) / ".zfs" / "snapshot" / name)
                snapshots.append({"dataset": dataset, "name": name})
                snapshots_by_dataset[dataset] = (name, snapshot_path)
                _persist_state()
            else:
                _, snapshot_path = current
            runtime_paths.append(snapshot_path)
        unique_paths = sorted(set(runtime_paths))
        state = {"schemaVersion": 1, "snapshots": snapshots, "nativeDumps": native_dumps}
        _write_atomic(paths_path, "".join(f"{path}\n" for path in unique_paths).encode("utf-8"), 0o640)
        _write_atomic(state_path, (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"), 0o600)
        return {"paths": unique_paths, "snapshots": snapshots, "nativeDumps": native_dumps}
    except Exception as exc:
        failures: list[str] = []
        for snapshot in reversed(snapshots):
            try:
                _run([zfs_bin, "destroy", f"{snapshot['dataset']}@{snapshot['name']}"])
            except BackupRuntimeError as destroy_exc:
                failures.append(f"{snapshot['dataset']}@{snapshot['name']}: {destroy_exc}")
        paths_path.unlink(missing_ok=True)
        state_path.unlink(missing_ok=True)
        if failures:
            raise BackupRuntimeError(
                f"backup preparation failed ({exc}); failed to clean snapshot(s): {'; '.join(failures)}"
            ) from exc
        raise


def cleanup(*, state_path: pathlib.Path, paths_path: pathlib.Path, zfs_bin: str) -> dict[str, Any]:
    if not state_path.exists():
        paths_path.unlink(missing_ok=True)
        return {"destroyed": []}
    state = _load_json(state_path)
    snapshots = state.get("snapshots")
    if state.get("schemaVersion") != 1 or not isinstance(snapshots, list):
        raise BackupRuntimeError("V2 backup runtime state has an unsupported schema")
    destroyed: list[str] = []
    failures: list[str] = []
    for snapshot in reversed(snapshots):
        if (
            not isinstance(snapshot, dict)
            or not isinstance(snapshot.get("dataset"), str)
            or not isinstance(snapshot.get("name"), str)
        ):
            failures.append("invalid snapshot state entry")
            continue
        reference = f"{snapshot['dataset']}@{snapshot['name']}"
        try:
            _run([zfs_bin, "destroy", reference])
            destroyed.append(reference)
        except BackupRuntimeError as exc:
            failures.append(f"{reference}: {exc}")
    if failures:
        raise BackupRuntimeError("failed to clean V2 backup snapshot(s): " + "; ".join(failures))
    state_path.unlink(missing_ok=True)
    paths_path.unlink(missing_ok=True)
    return {"destroyed": destroyed}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare or clean Managed Services V2 native backup resources")
    parser.add_argument("command", choices=("prepare", "cleanup"))
    parser.add_argument("--inventory", default="/run/nas-control/backup-resources.json")
    parser.add_argument("--paths", default="/run/nas-control/restic-v2-runtime-paths")
    parser.add_argument("--state", default="/run/nas-control/backup-runtime-state.json")
    parser.add_argument("--zfs", default="zfs")
    parser.add_argument("--systemctl", default="systemctl")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(
                inventory_path=pathlib.Path(args.inventory),
                paths_path=pathlib.Path(args.paths),
                state_path=pathlib.Path(args.state),
                zfs_bin=args.zfs,
                systemctl_bin=args.systemctl,
            )
        else:
            result = cleanup(
                state_path=pathlib.Path(args.state),
                paths_path=pathlib.Path(args.paths),
                zfs_bin=args.zfs,
            )
    except (BackupRuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"nas-v2-backup-runtime: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
