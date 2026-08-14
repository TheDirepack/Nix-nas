#!/usr/bin/env python3
"""Compile, prepare and verify Managed Services V2 backup resources.

Combined projection, runtime preparation/cleanup, restore verification and
native-dump resolution. No application names are recognized; native-dump
graphs are resolved generically from storage resources and job attachments.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any


class BackupProjectionError(RuntimeError):
    """Raised when a requested backup consistency mode is not safely available."""


class BackupRuntimeError(RuntimeError):
    """Raised when a native backup consistency operation cannot be completed safely."""


class BackupVerificationError(RuntimeError):
    """Raised when restored resource data cannot be verified safely."""


class NativeDumpProjectionError(RuntimeError):
    """Raised when a native-dump graph is ambiguous or unsafe."""


def _validate_absolute_path(value: Any) -> pathlib.PurePosixPath | None:
    if not isinstance(value, str) or any(c in value for c in ("\x00", "\r", "\n")):
        return None
    candidate = pathlib.PurePosixPath(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return None
    return candidate


def _safe_absolute_path(value: Any, *, label: str) -> str:
    if _validate_absolute_path(value) is None:
        raise BackupProjectionError(f"{label} is not a safe absolute path")
    assert isinstance(value, str)
    return value


def _absolute_path(value: Any, *, label: str) -> str:
    if _validate_absolute_path(value) is None:
        raise NativeDumpProjectionError(f"{label} is not a safe absolute path")
    assert isinstance(value, str)
    return value


def _absolute_source(value: Any, *, label: str) -> pathlib.PurePosixPath:
    candidate = _validate_absolute_path(value)
    if candidate is None:
        raise BackupVerificationError(f"{label} is not a safe absolute path")
    return candidate


def _runtime_safe_absolute_path(value: Any, *, label: str) -> str:
    try:
        return _safe_absolute_path(value, label=label)
    except BackupProjectionError:
        raise BackupRuntimeError(f"{label} is not a safe absolute path") from None


# ---------------------------------------------------------------------------
# Native-dump resolution
# ---------------------------------------------------------------------------


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
        artifact_ids = sorted(
            {
                str(attachment.get("resource"))
                for attachment in storage
                if isinstance(attachment, dict)
                and attachment.get("access", "read") == "write"
                and isinstance(attachment.get("resource"), str)
                and isinstance(resources.get(attachment.get("resource")), dict)
                and resources.get(attachment.get("resource"), {}).get("stateClass") == "derived"
            }
        )
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
    artifact_path = _absolute_path(artifact.get("path"), label=f"native-dump artifact {artifact_id!r} path")
    if artifact_path == source.get("path"):
        raise NativeDumpProjectionError("native-dump artifact path must differ from its authoritative source path")
    derived = effective.get("derived")
    runtimes = derived.get("runtime") if isinstance(derived, dict) else None
    runtime = runtimes.get(service_id) if isinstance(runtimes, dict) else None
    owner = runtime.get("ownerUnit") if isinstance(runtime, dict) else None
    if not isinstance(owner, str) or not owner.endswith(".service"):
        raise NativeDumpProjectionError(
            f"native-dump preparation job {service_id!r} is missing a concrete systemd owner unit"
        )
    return {
        "preparationService": service_id,
        "preparationUnit": owner,
        "artifactResource": artifact_id,
        "artifactPath": artifact_path,
    }


# ---------------------------------------------------------------------------
# Backup projection
# ---------------------------------------------------------------------------


def compile_backup_projection(effective: dict[str, Any]) -> tuple[bytes, bytes]:
    """Return a resource inventory JSON document and direct Restic path list.

    Filesystem-consistent resources can be consumed directly. ZFS snapshot and
    native-dump resources remain in the inventory and are prepared immediately
    before Restic executes by the runtime prepare step.
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
    document = {"schemaVersion": 1, "resources": inventory}
    path_list = "".join(f"{path}\n" for path in sorted(direct_paths)).encode("utf-8")
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"), path_list


# ---------------------------------------------------------------------------
# Backup runtime (prepare / cleanup)
# ---------------------------------------------------------------------------


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
            _runtime_safe_absolute_path(path, label=f"backup resource {resource_id!r} path")
            assert isinstance(path, str)
            if consistency in {"filesystem", "none"}:
                runtime_paths.append(path)
                continue
            if consistency == "native-dump":
                artifact_path, prepared = _native_dump_path(resource_id, resource, systemctl_bin=systemctl_bin)
                _runtime_safe_absolute_path(artifact_path, label=f"backup resource {resource_id!r} native-dump artifactPath")
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


def build_verify_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify a restored Managed Services V2 backup by resource")
    parser.add_argument("--inventory", default="/run/nas-control/backup-resources.json")
    parser.add_argument("--restore-root", required=True)
    parser.add_argument("--pg-restore", default="pg_restore")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    # Allow verify sub-invocation via same entrypoint when invoked as backup-verify
    if argv is not None and "--restore-root" in argv:
        return verify_main(argv)
    args = parser.parse_args(argv)
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


# ---------------------------------------------------------------------------
# Restore verification
# ---------------------------------------------------------------------------


def _load_inventory(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupVerificationError(f"unable to read compiled backup inventory {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 1 or not isinstance(value.get("resources"), list):
        raise BackupVerificationError("compiled V2 backup inventory has an unsupported schema")
    return value


def _restored_path(root: pathlib.Path, source: pathlib.PurePosixPath) -> pathlib.Path:
    candidate = root.joinpath(*source.parts[1:])
    resolved_root = root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise BackupVerificationError(f"restored source {source} escapes verification root {root}") from exc
    return candidate


def _assert_within_restore_root(path: pathlib.Path, restore_root: pathlib.Path) -> None:
    resolved_root = restore_root.resolve()
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise BackupVerificationError(f"restored file {path} escapes verification root {restore_root}") from exc


def _resource_candidates(root: pathlib.Path, resource: dict[str, Any]) -> list[pathlib.Path]:
    resource_id = resource.get("id")
    consistency = resource.get("consistency")
    if not isinstance(resource_id, str) or not isinstance(consistency, str):
        raise BackupVerificationError("compiled V2 backup inventory contains an invalid resource")
    if consistency == "native-dump":
        native_dump = resource.get("nativeDump")
        artifact_path = native_dump.get("artifactPath") if isinstance(native_dump, dict) else None
        source = _absolute_source(artifact_path, label=f"native-dump resource {resource_id!r} artifactPath")
        return [_restored_path(root, source)]
    source = _absolute_source(resource.get("path"), label=f"backup resource {resource_id!r} path")
    direct = _restored_path(root, source)
    if consistency in {"filesystem", "none"}:
        return [direct]
    if consistency != "zfs-snapshot":
        raise BackupVerificationError(f"backup resource {resource_id!r} has unsupported consistency {consistency!r}")
    snapshot_root = direct / ".zfs" / "snapshot"
    if snapshot_root.is_symlink():
        raise BackupVerificationError(f"restored ZFS snapshot root for {resource_id!r} must not be a symlink")
    try:
        candidates = sorted(
            path
            for path in snapshot_root.iterdir()
            if not path.is_symlink() and path.is_dir() and path.name.startswith("nas-v2-restic-")
        )
        non_empty: list[pathlib.Path] = []
        for candidate in candidates:
            try:
                if candidate.is_symlink():
                    continue
                if any(candidate.iterdir()):
                    non_empty.append(candidate)
            except OSError as exc:
                raise BackupVerificationError(
                    f"unable to inspect restored ZFS snapshot {candidate} for {resource_id!r}: {exc}"
                ) from exc
        if candidates and not non_empty:
            return []
        return non_empty
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise BackupVerificationError(
            f"unable to inspect restored ZFS snapshot tree for {resource_id!r}: {exc}"
        ) from exc


def _native_dump_files(path: pathlib.Path) -> list[pathlib.Path]:
    if path.is_symlink():
        raise BackupVerificationError(f"native-dump artifact must not be a symlink: {path}")
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    files: list[pathlib.Path] = []
    try:
        for candidate in path.rglob("*"):
            if candidate.is_symlink():
                raise BackupVerificationError(f"native-dump artifact contains a symlink: {candidate}")
            if candidate.is_file():
                files.append(candidate)
    except OSError as exc:
        raise BackupVerificationError(f"unable to enumerate native-dump artifact {path}: {exc}") from exc
    return sorted(files)


def _has_prefix(path: pathlib.Path, prefix: bytes, *, restore_root: pathlib.Path) -> bool:
    _assert_within_restore_root(path, restore_root)
    try:
        with path.open("rb") as handle:
            return handle.read(len(prefix)) == prefix
    except OSError as exc:
        raise BackupVerificationError(f"unable to inspect restored file {path}: {exc}") from exc


def _verify_sqlite(path: pathlib.Path, *, restore_root: pathlib.Path) -> None:
    _assert_within_restore_root(path, restore_root)
    try:
        uri = f"{path.resolve().as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as database:
            rows = database.execute("PRAGMA integrity_check").fetchall()
    except (OSError, sqlite3.Error) as exc:
        raise BackupVerificationError(f"SQLite integrity verification failed for {path}: {exc}") from exc
    if rows != [("ok",)]:
        detail = "; ".join(str(row[0]) for row in rows) if rows else "no result"
        raise BackupVerificationError(f"SQLite integrity verification failed for {path}: {detail}")


def _verify_postgresql_custom_dump(path: pathlib.Path, *, pg_restore_bin: str, restore_root: pathlib.Path) -> None:
    _assert_within_restore_root(path, restore_root)
    try:
        result = subprocess.run(
            [pg_restore_bin, "--list", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise BackupVerificationError(f"unable to execute pg_restore for {path}: {exc}") from exc
    if result.returncode != 0 or not result.stdout.strip():
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        raise BackupVerificationError(f"PostgreSQL custom dump verification failed for {path}: {detail}")


def _verify_native_dump_files(
    files: list[pathlib.Path], *, pg_restore_bin: str, restore_root: pathlib.Path
) -> dict[str, int]:
    checks = {"sqlite": 0, "postgresqlCustom": 0}
    for path in files:
        if _has_prefix(path, b"SQLite format 3\x00", restore_root=restore_root):
            _verify_sqlite(path, restore_root=restore_root)
            checks["sqlite"] += 1
            continue
        if _has_prefix(path, b"PGDMP", restore_root=restore_root):
            _verify_postgresql_custom_dump(path, pg_restore_bin=pg_restore_bin, restore_root=restore_root)
            checks["postgresqlCustom"] += 1
    return checks


def verify(*, inventory_path: pathlib.Path, restore_root: pathlib.Path, pg_restore_bin: str) -> dict[str, Any]:
    inventory = _load_inventory(inventory_path)
    if not restore_root.is_dir():
        raise BackupVerificationError(f"restore root does not exist or is not a directory: {restore_root}")
    verified: list[dict[str, Any]] = []
    for raw_resource in inventory["resources"]:
        if not isinstance(raw_resource, dict):
            raise BackupVerificationError("compiled V2 backup inventory contains an invalid resource")
        resource_id = raw_resource.get("id")
        consistency = raw_resource.get("consistency")
        if not isinstance(resource_id, str) or not isinstance(consistency, str):
            raise BackupVerificationError("compiled V2 backup inventory contains an invalid resource")
        candidates = _resource_candidates(restore_root, raw_resource)
        if not candidates:
            raise BackupVerificationError(f"restored backup resource {resource_id!r} is missing")
        for candidate in candidates:
            if not candidate.exists():
                raise BackupVerificationError(f"restored backup resource {resource_id!r} is missing at {candidate}")
        files: list[pathlib.Path] = []
        checks = {"sqlite": 0, "postgresqlCustom": 0}
        if consistency == "native-dump":
            for candidate in candidates:
                files.extend(_native_dump_files(candidate))
            for candidate_file in files:
                _assert_within_restore_root(candidate_file, restore_root)
            if not any(path.stat().st_size > 0 for path in files):
                raise BackupVerificationError(
                    f"native-dump resource {resource_id!r} restored no non-empty artifact files"
                )
            checks = _verify_native_dump_files(files, pg_restore_bin=pg_restore_bin, restore_root=restore_root)
        verified.append(
            {
                "id": resource_id,
                "consistency": consistency,
                "sources": [str(path) for path in candidates],
                "files": len(files),
                "checks": checks,
            }
        )
    return {"schemaVersion": 1, "resources": verified}


def verify_main(argv: list[str] | None = None) -> int:
    parser = build_verify_parser()
    args = parser.parse_args(argv)
    try:
        result = verify(
            inventory_path=pathlib.Path(args.inventory),
            restore_root=pathlib.Path(args.restore_root),
            pg_restore_bin=args.pg_restore,
        )
    except BackupVerificationError as exc:
        print(f"nas-v2-backup-verify: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


__all__ = [
    "BackupProjectionError",
    "BackupRuntimeError",
    "BackupVerificationError",
    "NativeDumpProjectionError",
    "compile_backup_projection",
    "resolve_native_dump",
    "prepare",
    "cleanup",
    "build_parser",
    "build_verify_parser",
    "verify",
    "verify_main",
    "main",
]
