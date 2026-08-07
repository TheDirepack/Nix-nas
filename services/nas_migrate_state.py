#!/usr/bin/env python3
"""Plan and apply explicit migrations for mutable NAS control-plane state.

Migrations are narrow, backup-first, and lock-protected. The tool never rewrites
an unknown schema or deletes fields it does not understand. ``plan`` is safe
for unprivileged diagnostics; ``apply`` requires
root unless the test-only ``NAS_MIGRATE_ALLOW_UNPRIVILEGED=1`` override is set.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import stat
import tempfile
import time
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from nas_feature_model import entry_allowed_modes, entry_default_mode, migrate_mode
from nas_operation_lock import OperationBusyError, acquire_operation

FEATURE_STATE = pathlib.Path(os.environ.get("NAS_FEATURE_STATE", "/var/lib/nas-control/settings.json"))
FEATURE_CATALOG = pathlib.Path(os.environ.get("NAS_FEATURE_CATALOG", "/etc/nas-control/features.json"))
SETUP_STATE = pathlib.Path(os.environ.get("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json"))
MIGRATION_ROOT = pathlib.Path(os.environ.get("NAS_MIGRATION_ROOT", "/var/lib/nas-migrations"))
TARGET_FEATURE_SCHEMA = 2
TARGET_SETUP_SCHEMA = 1


class MigrationError(RuntimeError):
    """A state file cannot be safely migrated."""


@dataclass(frozen=True)
class MigrationItem:
    authority: str
    path: str
    status: str
    current_schema: int | None
    target_schema: int
    detail: str
    backup: str | None = None


@dataclass(frozen=True)
class PlannedMigration:
    item: MigrationItem
    value: dict[str, Any] | None = None
    mode: int = 0o600


def _read_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationError(f"Invalid JSON state file: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MigrationError(f"State file must contain a JSON object: {path}")
    return value


def _schema(value: Mapping[str, Any]) -> int | None:
    raw = value.get("schemaVersion")
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise MigrationError("schemaVersion must be an integer")
    return raw


def _secure_regular_file(path: pathlib.Path) -> int:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise MigrationError(f"State authority must be a regular non-symlink file: {path}")
    return stat.S_IMODE(metadata.st_mode) & 0o777


def _load_feature_catalog(path: pathlib.Path) -> dict[str, dict[str, Any]]:
    value = _read_object(path)
    features = value.get("features")
    if not isinstance(features, dict) or not features:
        raise MigrationError("Feature catalog contains no features")
    normalized: dict[str, dict[str, Any]] = {}
    for feature_id, entry in features.items():
        if not isinstance(feature_id, str) or not isinstance(entry, dict):
            raise MigrationError("Feature catalog contains a malformed entry")
        allowed = entry_allowed_modes(entry)
        if not allowed or "off" not in allowed:
            raise MigrationError(f"Feature {feature_id} has no safe off mode")
        normalized[feature_id] = entry
    return normalized


def _validate_feature_state(value: Mapping[str, Any], features: Mapping[str, Mapping[str, Any]]) -> None:
    if set(value) - {"schemaVersion", "features", "updatedAt"}:
        raise MigrationError("Feature state contains unknown top-level fields")
    raw = value.get("features")
    if not isinstance(raw, dict):
        raise MigrationError("Feature state features must be an object")
    unknown = sorted(set(raw) - set(features))
    if unknown:
        raise MigrationError(f"Feature state contains unknown feature(s): {', '.join(unknown)}")
    missing = sorted(set(features) - set(raw))
    if missing:
        raise MigrationError(f"Feature state omits configured feature(s): {', '.join(missing)}")
    for feature_id, entry in features.items():
        mode = raw[feature_id]
        if not isinstance(mode, str) or mode not in entry_allowed_modes(dict(entry)):
            raise MigrationError(f"Feature {feature_id} has an invalid mode")
    updated = value.get("updatedAt")
    if isinstance(updated, bool) or not isinstance(updated, int) or updated < 0:
        raise MigrationError("Feature state updatedAt must be a non-negative integer")


def plan_feature_state(
    path: pathlib.Path = FEATURE_STATE,
    catalog_path: pathlib.Path = FEATURE_CATALOG,
) -> PlannedMigration:
    try:
        value = _read_object(path)
    except FileNotFoundError:
        return PlannedMigration(
            MigrationItem(
                "feature-control",
                str(path),
                "absent",
                None,
                TARGET_FEATURE_SCHEMA,
                "No mutable feature state exists yet",
            )
        )
    mode = _secure_regular_file(path)
    features = _load_feature_catalog(catalog_path)
    current = _schema(value)
    if current == TARGET_FEATURE_SCHEMA:
        _validate_feature_state(value, features)
        return PlannedMigration(
            MigrationItem(
                "feature-control",
                str(path),
                "current",
                current,
                TARGET_FEATURE_SCHEMA,
                "Feature state already matches the current schema",
            )
        )
    if current not in {None, 1}:
        return PlannedMigration(
            MigrationItem(
                "feature-control",
                str(path),
                "unsupported",
                current,
                TARGET_FEATURE_SCHEMA,
                "No registered feature-state migration path",
            )
        )
    raw = value.get("features", {})
    if not isinstance(raw, dict):
        raise MigrationError("Legacy feature state features must be an object")
    unknown = sorted(set(raw) - set(features))
    if unknown:
        raise MigrationError(f"Legacy feature state contains unknown feature(s): {', '.join(unknown)}")
    migrated: dict[str, str] = {}
    for feature_id, entry in features.items():
        source = raw.get(feature_id, entry_default_mode(entry))
        result = migrate_mode(source, entry)
        if result is None:
            raise MigrationError(f"Legacy feature {feature_id} cannot be migrated safely")
        migrated[feature_id] = result
    output: dict[str, Any] = {
        "schemaVersion": TARGET_FEATURE_SCHEMA,
        "features": migrated,
        "updatedAt": int(time.time()),
    }
    _validate_feature_state(output, features)
    return PlannedMigration(
        MigrationItem(
            "feature-control",
            str(path),
            "migration-required",
            current,
            TARGET_FEATURE_SCHEMA,
            "Convert legacy boolean feature flags to explicit lifecycle modes",
        ),
        output,
        mode,
    )


def plan_setup_state(path: pathlib.Path = SETUP_STATE) -> PlannedMigration:
    try:
        value = _read_object(path)
    except FileNotFoundError:
        return PlannedMigration(
            MigrationItem(
                "first-run", str(path), "absent", None, TARGET_SETUP_SCHEMA, "No completed setup state exists yet"
            )
        )
    mode = _secure_regular_file(path)
    current = _schema(value)
    if current == TARGET_SETUP_SCHEMA:
        if value.get("status") not in {"complete", "complete-unverified"}:
            raise MigrationError("Setup state has an invalid completion status")
        if not isinstance(value.get("planDigest"), str) or len(value["planDigest"]) != 64:
            raise MigrationError("Setup state has an invalid plan digest")
        return PlannedMigration(
            MigrationItem(
                "first-run",
                str(path),
                "current",
                current,
                TARGET_SETUP_SCHEMA,
                "Setup state already matches the current schema",
            ),
            mode=mode,
        )
    return PlannedMigration(
        MigrationItem(
            "first-run",
            str(path),
            "unsupported",
            current,
            TARGET_SETUP_SCHEMA,
            "Unknown setup-state schemas require explicit operator recovery",
        ),
        mode=mode,
    )


def plan_all() -> list[PlannedMigration]:
    return [plan_feature_state(), plan_setup_state()]


def require_root() -> None:
    if os.geteuid() != 0 and os.environ.get("NAS_MIGRATE_ALLOW_UNPRIVILEGED") != "1":
        raise MigrationError("nas-migrate-state apply requires root")


def _atomic_write(path: pathlib.Path, value: Mapping[str, Any], mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    replaced = False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(dict(value), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        replaced = True
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if not replaced:
            pathlib.Path(temporary).unlink(missing_ok=True)


def apply_all(plans: list[PlannedMigration] | None = None) -> dict[str, Any]:
    require_root()
    selected = plans if plans is not None else plan_all()
    unsupported = [item.item for item in selected if item.item.status == "unsupported"]
    if unsupported:
        names = ", ".join(item.authority for item in unsupported)
        raise MigrationError(f"Unsupported state schema(s) require manual recovery: {names}")
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_root = MIGRATION_ROOT / run_id
    applied: list[MigrationItem] = []
    with acquire_operation("state-schema-migration", ("appliance", "runtime", "state"), blocking=False):
        for plan in selected:
            if plan.item.status != "migration-required" or plan.value is None:
                applied.append(plan.item)
                continue
            source = pathlib.Path(plan.item.path)
            backup = backup_root / plan.item.authority / source.name
            backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(source, backup, follow_symlinks=False)
            os.chmod(backup, 0o600)
            _atomic_write(source, plan.value, plan.mode)
            applied.append(MigrationItem(**{**asdict(plan.item), "status": "migrated", "backup": str(backup)}))
    if backup_root.exists():
        os.chmod(backup_root, 0o700)
    return {
        "schemaVersion": 1,
        "status": "complete",
        "runId": run_id,
        "backupRoot": str(backup_root) if backup_root.exists() else None,
        "items": [asdict(item) for item in applied],
    }


def report(plans: list[PlannedMigration]) -> dict[str, Any]:
    statuses = [plan.item.status for plan in plans]
    if "unsupported" in statuses:
        status = "manual-recovery-required"
    elif "migration-required" in statuses:
        status = "migration-required"
    else:
        status = "current"
    return {"schemaVersion": 1, "status": status, "items": [asdict(plan.item) for plan in plans]}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    sub = value.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="Show required and unsupported migrations without modifying state")
    apply = sub.add_parser("apply", help="Back up and apply every registered migration under the appliance lock")
    apply.add_argument("--confirm", required=True, choices=["APPLY_STATE_MIGRATIONS"])
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        plans = plan_all()
        if args.command == "plan":
            payload = report(plans)
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 2 if payload["status"] == "manual-recovery-required" else 0
        payload = apply_all(plans)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (MigrationError, OperationBusyError) as exc:
        print(json.dumps({"schemaVersion": 1, "status": "error", "error": str(exc)}, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
