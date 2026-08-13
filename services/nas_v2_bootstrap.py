#!/usr/bin/env python3
"""Seed the Nix-provided Managed Services V2 baseline exactly once.

The durable ``services.yaml`` authority belongs to the administrator after it is
created. Nix may provide the initial baseline only when the seed service observed
that no authority existed before its ExecStart. The marker passed to this helper
is therefore a one-shot *pre-existence sentinel*, not a database of previously
seen application keys and not an upgrade merge mechanism.
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

from nas_v2_spec import ManagedServicesV2Error, compile_document, load_platform_capabilities, load_schema


class BootstrapError(RuntimeError):
    """Raised when the one-time V2 baseline cannot be seeded safely."""


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


def _is_directory_desired(path: pathlib.Path) -> bool:
    if path.is_dir():
        return True
    if path.is_file():
        return False
    return path.suffix.lower() not in {".yaml", ".yml"}


def _yaml_files(directory: pathlib.Path) -> list[pathlib.Path]:
    try:
        entries = list(directory.iterdir())
    except FileNotFoundError:
        return []
    files = [p for p in entries if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}]
    return sorted(files, key=lambda p: p.name)


def _load_desired(path: pathlib.Path) -> CommentedMap:
    if path.is_dir():
        files = _yaml_files(path)
        if not files:
            stub = CommentedMap()
            stub["schemaVersion"] = 3
            stub["services"] = CommentedMap()
            return stub
        merged: CommentedMap | None = None
        for f in files:
            doc = _load(f)
            if merged is None:
                merged = doc
            else:
                for key, value in doc.items():
                    if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                        base = merged[key]
                        if isinstance(base, dict):
                            for k2, v2 in value.items():
                                base[k2] = v2
                        else:
                            merged[key] = value
                    else:
                        merged[key] = value
        assert merged is not None
        return merged
    if _is_directory_desired(path) and not path.exists():
        stub = CommentedMap()
        stub["schemaVersion"] = 3
        stub["services"] = CommentedMap()
        return stub
    return _load(path)


def _atomic_dump_desired(path: pathlib.Path, document: CommentedMap) -> None:
    if path.is_dir() or (_is_directory_desired(path) and not path.exists()):
        target_dir = path if path.is_dir() or not path.exists() else path.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "00-default.yaml"
        _atomic_dump(target, document)
        return
    if _is_directory_desired(path) and path.exists() and not path.is_dir():
        _atomic_dump(path, document)
        return
    if path.is_dir():
        target = path / "00-default.yaml"
        _atomic_dump(target, document)
        for f in _yaml_files(path):
            if f != target:
                try:
                    f.unlink()
                except OSError:
                    pass
        return
    _atomic_dump(path, document)


def _validate(
    document: CommentedMap,
    *,
    schema_path: pathlib.Path,
    platform_path: pathlib.Path | None,
) -> None:
    schema = load_schema(schema_path)
    capabilities = None if platform_path is None else load_platform_capabilities(platform_path)
    compile_document(document, schema, platform_capabilities=capabilities)


def _fsync_directory(directory: pathlib.Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
        _fsync_directory(path.parent)
        raw_tmp = None
    finally:
        if raw_tmp is not None:
            pathlib.Path(raw_tmp).unlink(missing_ok=True)


def _is_seed_stub(document: CommentedMap) -> bool:
    """Recognize only the minimal authority stub created by the base seed unit."""
    return (
        set(document) == {"schemaVersion", "services"}
        and document.get("schemaVersion") == 3
        and document.get("services") == {}
    )


def _clear_marker(marker: pathlib.Path) -> None:
    try:
        marker.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(marker.parent)


def _authority_lock(path: pathlib.Path):
    import fcntl
    from contextlib import contextmanager

    @contextmanager
    def _lock():
        lock_path = path.with_name(f".{path.name}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    return _lock()


def migrate(
    *,
    desired: pathlib.Path,
    seed: pathlib.Path,
    marker: pathlib.Path,
    schema: pathlib.Path,
    platform: pathlib.Path | None,
) -> dict[str, Any]:
    """Install the baseline only when the seed unit proved no prior authority existed."""
    # Use authority lock to serialize concurrent first-start attempts so only one
    # complete authority is ever created and no partial union occurs.
    with _authority_lock(desired):
        if not marker.exists():
            return {
                "changed": False,
                "reason": "authority-exists",
            }

        current = _load_desired(desired)
        if not _is_seed_stub(current):
            # A concurrent writer won the race between preStart and ExecStart. Never
            # overwrite that authority merely because the one-shot marker exists.
            _clear_marker(marker)
            return {
                "changed": False,
                "reason": "authority-created-concurrently",
            }

        baseline = _load(seed)
        if baseline.get("schemaVersion") != 3:
            raise BootstrapError("initial baseline must use schemaVersion 3")
        _validate(baseline, schema_path=schema, platform_path=platform)
        _atomic_dump_desired(desired, baseline)
        _clear_marker(marker)

        services = baseline.get("services")
        return {
            "changed": True,
            "reason": "initial-seed",
            "services": len(services) if isinstance(services, dict) else 0,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the initial Managed Services V2 baseline")
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
    except (BootstrapError, ManagedServicesV2Error, OSError, ValueError) as exc:
        print(f"nas-v2-bootstrap: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["BootstrapError", "migrate"]
