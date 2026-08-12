#!/usr/bin/env python3
"""Resource-oriented restore verification for Managed Services V2 backups.

The verifier consumes the compiled backup inventory and restored Restic tree. It
never recognizes application names. Generic format checks are selected from the
restored data itself so native-dump resources can be validated without adding
application branches to the backup/restore engine.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any


class BackupVerificationError(RuntimeError):
    """Raised when restored resource data cannot be verified safely."""


def _load_inventory(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupVerificationError(f"unable to read compiled backup inventory {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 1 or not isinstance(value.get("resources"), list):
        raise BackupVerificationError("compiled V2 backup inventory has an unsupported schema")
    return value


def _absolute_source(value: Any, *, label: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or any(character in value for character in ("\x00", "\r", "\n")):
        raise BackupVerificationError(f"{label} is not a safe absolute path")
    source = pathlib.PurePosixPath(value)
    if not source.is_absolute() or ".." in source.parts:
        raise BackupVerificationError(f"{label} is not a safe absolute path")
    return source


def _restored_path(root: pathlib.Path, source: pathlib.PurePosixPath) -> pathlib.Path:
    candidate = root.joinpath(*source.parts[1:])
    resolved_root = root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise BackupVerificationError(f"restored source {source} escapes verification root {root}") from exc
    return candidate


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
    try:
        return sorted(path for path in snapshot_root.iterdir() if path.is_dir())
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise BackupVerificationError(f"unable to inspect restored ZFS snapshot tree for {resource_id!r}: {exc}") from exc


def _regular_files(path: pathlib.Path) -> list[pathlib.Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    try:
        return sorted(candidate for candidate in path.rglob("*") if candidate.is_file())
    except OSError as exc:
        raise BackupVerificationError(f"unable to enumerate restored resource {path}: {exc}") from exc


def _looks_like_sqlite(path: pathlib.Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(16) == b"SQLite format 3\x00"
    except OSError as exc:
        raise BackupVerificationError(f"unable to inspect restored file {path}: {exc}") from exc


def _looks_like_postgresql_custom_dump(path: pathlib.Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(5) == b"PGDMP"
    except OSError as exc:
        raise BackupVerificationError(f"unable to inspect restored file {path}: {exc}") from exc


def _verify_sqlite(path: pathlib.Path) -> None:
    try:
        uri = f"file:{path}?mode=ro"
        with sqlite3.connect(uri, uri=True) as database:
            rows = database.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.Error as exc:
        raise BackupVerificationError(f"SQLite integrity verification failed for {path}: {exc}") from exc
    if rows != [("ok",)]:
        detail = "; ".join(str(row[0]) for row in rows) if rows else "no result"
        raise BackupVerificationError(f"SQLite integrity verification failed for {path}: {detail}")


def _verify_xml(path: pathlib.Path) -> None:
    try:
        ET.parse(path)
    except (ET.ParseError, OSError) as exc:
        raise BackupVerificationError(f"XML verification failed for {path}: {exc}") from exc


def _verify_postgresql_custom_dump(path: pathlib.Path, *, pg_restore_bin: str) -> None:
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


def _verify_files(files: list[pathlib.Path], *, pg_restore_bin: str) -> dict[str, int]:
    checks = {"sqlite": 0, "xml": 0, "postgresqlCustom": 0}
    for path in files:
        if _looks_like_sqlite(path):
            _verify_sqlite(path)
            checks["sqlite"] += 1
            continue
        if _looks_like_postgresql_custom_dump(path):
            _verify_postgresql_custom_dump(path, pg_restore_bin=pg_restore_bin)
            checks["postgresqlCustom"] += 1
            continue
        if path.suffix.lower() == ".xml":
            _verify_xml(path)
            checks["xml"] += 1
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
        files: list[pathlib.Path] = []
        for candidate in candidates:
            candidate_files = _regular_files(candidate)
            if not candidate.exists():
                raise BackupVerificationError(f"restored backup resource {resource_id!r} is missing at {candidate}")
            files.extend(candidate_files)
        if consistency == "native-dump" and not any(path.stat().st_size > 0 for path in files):
            raise BackupVerificationError(f"native-dump resource {resource_id!r} restored no non-empty artifact files")

        checks = _verify_files(files, pg_restore_bin=pg_restore_bin)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify a restored Managed Services V2 backup by resource")
    parser.add_argument("--inventory", default="/run/nas-control/backup-resources.json")
    parser.add_argument("--restore-root", required=True)
    parser.add_argument("--pg-restore", default="pg_restore")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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


if __name__ == "__main__":
    raise SystemExit(main())
