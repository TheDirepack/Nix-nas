#!/usr/bin/env python3
"""Additively migrate Nix-provided baseline objects into Managed Services V2.

The migration remembers every baseline key it has already seen. A later release
may add new baseline services/resources and those new keys are merged once, but
an administrator who deletes or replaces a previously seeded key remains
authoritative: previously seen keys are never re-added or overwritten.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import tempfile
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from nas_v2_spec import compile_document, load_platform_capabilities, load_schema


class BootstrapError(RuntimeError):
    """Raised when a bootstrap migration cannot be applied safely."""


_MERGE_MAPS = ("storageResources", "credentials", "networkProfiles", "services")
_MARKER_SCHEMA = 2


def _yaml() -> YAML:
    parser = YAML(typ="rt", pure=True)
    parser.version = (1, 2)
    parser.allow_duplicate_keys = False
    parser.preserve_quotes = True
    return parser


def _load(path: pathlib.Path) -> CommentedMap:
    parser = _yaml()
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = parser.load(handle)
    except OSError as exc:
        raise BootstrapError(f"unable to read {path}: {exc}") from exc
    if not isinstance(value, CommentedMap):
        raise BootstrapError(f"{path} must contain a YAML mapping")
    return value


def _seed_keys(seed: CommentedMap) -> set[str]:
    keys: set[str] = set()
    for section in _MERGE_MAPS:
        seed_section = seed.get(section)
        if seed_section is None:
            continue
        if not isinstance(seed_section, dict):
            raise BootstrapError(f"seed section {section!r} must be a mapping")
        keys.update(f"{section}.{key}" for key in seed_section)
    return keys


def _load_seen(marker: pathlib.Path) -> set[str]:
    if not marker.exists():
        return set()
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"invalid bootstrap marker {marker}: {exc}") from exc
    if not isinstance(value, dict):
        raise BootstrapError("bootstrap marker must contain a JSON object")
    # Marker schema 1 was used by the in-development first implementation. Treat
    # its exact added keys as already seen while allowing keys that were present
    # in services.yaml at the time to be discovered by the current seed below.
    if value.get("schemaVersion") in {None, 1}:
        added = value.get("added", [])
        if not isinstance(added, list) or not all(isinstance(item, str) for item in added):
            raise BootstrapError("legacy bootstrap marker contains an invalid added list")
        return set(added)
    if value.get("schemaVersion") != _MARKER_SCHEMA:
        raise BootstrapError("bootstrap marker uses an unsupported schemaVersion")
    seen = value.get("seen", [])
    if not isinstance(seen, list) or not all(isinstance(item, str) for item in seen):
        raise BootstrapError("bootstrap marker contains an invalid seen list")
    return set(seen)


def _merge_new_keys(current: CommentedMap, seed: CommentedMap, *, seen: set[str]) -> list[str]:
    added: list[str] = []
    for section in _MERGE_MAPS:
        seed_section = seed.get(section)
        if seed_section is None:
            continue
        if not isinstance(seed_section, dict):
            raise BootstrapError(f"seed section {section!r} must be a mapping")
        current_section = current.get(section)
        if current_section is None:
            current_section = CommentedMap()
            current[section] = current_section
        if not isinstance(current_section, dict):
            raise BootstrapError(f"existing section {section!r} must be a mapping")
        for key, value in seed_section.items():
            canonical = f"{section}.{key}"
            if canonical in seen or key in current_section:
                continue
            current_section[key] = value
            added.append(canonical)
    return added


def _validate(
    document: CommentedMap,
    *,
    schema_path: pathlib.Path,
    platform_path: pathlib.Path | None,
) -> None:
    schema = load_schema(schema_path)
    capabilities = None if platform_path is None else load_platform_capabilities(platform_path)
    compile_document(document, schema, platform_capabilities=capabilities)


def _atomic_dump(path: pathlib.Path, document: CommentedMap) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_stat = path.stat() if path.exists() else None
    parser = _yaml()
    raw_tmp: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            raw_tmp = handle.name
            parser.dump(document, handle)
            handle.flush()
            os.fsync(handle.fileno())
        tmp = pathlib.Path(raw_tmp)
        if existing_stat is not None:
            os.chmod(tmp, existing_stat.st_mode & 0o7777)
            try:
                os.chown(tmp, existing_stat.st_uid, existing_stat.st_gid)
            except PermissionError:
                pass
        else:
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        raw_tmp = None
    finally:
        if raw_tmp is not None:
            pathlib.Path(raw_tmp).unlink(missing_ok=True)


def _atomic_marker(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, raw_tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = pathlib.Path(raw_tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def migrate(
    *,
    desired: pathlib.Path,
    seed: pathlib.Path,
    marker: pathlib.Path,
    schema: pathlib.Path,
    platform: pathlib.Path | None,
) -> dict[str, Any]:
    """Merge only previously unseen baseline keys and record the complete seed set."""
    current = _load(desired)
    baseline = _load(seed)
    if current.get("schemaVersion") != 3 or baseline.get("schemaVersion") != 3:
        raise BootstrapError("bootstrap migration requires schemaVersion 3 documents")

    seen = _load_seen(marker)
    current_seed_keys = _seed_keys(baseline)
    pending = current_seed_keys - seen
    if not pending:
        return {
            "changed": False,
            "reason": "seed-current",
            "added": [],
            "seen": sorted(seen),
        }

    added = _merge_new_keys(current, baseline, seen=seen)
    _validate(current, schema_path=schema, platform_path=platform)
    if added:
        _atomic_dump(desired, current)

    # Every key in this seed is now considered applied even when it was already
    # present in administrator-owned desired state. That is what prevents a later
    # deletion from being silently reintroduced on the next boot.
    updated_seen = seen | current_seed_keys
    result = {
        "schemaVersion": _MARKER_SCHEMA,
        "changed": bool(added),
        "reason": "seed-updated",
        "added": added,
        "seen": sorted(updated_seen),
    }
    _atomic_marker(marker, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Additively migrate Managed Services V2 baseline objects")
    parser.add_argument("--desired", required=True, type=pathlib.Path)
    parser.add_argument("--seed", required=True, type=pathlib.Path)
    parser.add_argument("--marker", required=True, type=pathlib.Path)
    parser.add_argument("--schema", required=True, type=pathlib.Path)
    parser.add_argument("--platform", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        result = migrate(
            desired=args.desired,
            seed=args.seed,
            marker=args.marker,
            schema=args.schema,
            platform=args.platform,
        )
    except (BootstrapError, OSError, ValueError) as exc:
        print(f"nas-v2-bootstrap: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["BootstrapError", "migrate"]
