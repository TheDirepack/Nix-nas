#!/usr/bin/env python3
"""Activate V2-owned firewalld files with rollback and one native reload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


class FirewalldReconcileError(RuntimeError):
    """Raised when V2 firewalld state cannot be reconciled safely."""


_OWNED_FILE = re.compile(r"^nv2[zhwlri][0-9a-f]{12}\.xml$")


def _read_manifest(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FirewalldReconcileError(f"unable to read firewalld manifest {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 1 or not isinstance(value.get("files"), list):
        raise FirewalldReconcileError("firewalld projection manifest is invalid")
    return value


def _safe_target(relative: str) -> pathlib.PurePosixPath:
    target = pathlib.PurePosixPath(relative)
    if len(target.parts) != 2 or target.parts[0] not in {"zones", "policies"}:
        raise FirewalldReconcileError(f"unsafe firewalld target {relative!r}")
    if not _OWNED_FILE.fullmatch(target.name):
        raise FirewalldReconcileError(f"firewalld target {relative!r} is outside the V2 ownership namespace")
    return target


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewalldReconcileError(f"unable to execute {command[0]}: {exc}") from exc


def _atomic_copy(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temp = pathlib.Path(raw_temp)
    replaced = False
    try:
        with source.open("rb") as reader, os.fdopen(fd, "wb") as writer:
            shutil.copyfileobj(reader, writer)
            writer.flush()
            os.fsync(writer.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, destination)
        replaced = True
    finally:
        if not replaced:
            temp.unlink(missing_ok=True)


def _fsync(directory: pathlib.Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def reconcile(
    *,
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
    system_config: pathlib.Path,
    firewall_cmd: str,
    firewall_offline_cmd: str,
) -> dict[str, Any]:
    manifest = _read_manifest(manifest_path)
    desired: dict[pathlib.PurePosixPath, tuple[pathlib.Path, str]] = {}
    for entry in manifest["files"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("target"), str)
            or not isinstance(entry.get("sha256"), str)
        ):
            raise FirewalldReconcileError("firewalld manifest file entry is invalid")
        relative = _safe_target(entry["target"])
        source = projection_root / str(relative)
        try:
            source.relative_to(projection_root)
        except ValueError as exc:
            raise FirewalldReconcileError(f"projection source escapes root: {source}") from exc
        if not source.is_file() or _sha256(source) != entry["sha256"]:
            raise FirewalldReconcileError(f"projected firewalld file is missing or changed: {source}")
        desired[relative] = (source, entry["sha256"])

    current: set[pathlib.PurePosixPath] = set()
    for directory_name in ("zones", "policies"):
        directory = system_config / directory_name
        directory.mkdir(parents=True, exist_ok=True)
        for path in directory.iterdir():
            if path.is_file() and _OWNED_FILE.fullmatch(path.name):
                current.add(pathlib.PurePosixPath(directory_name) / path.name)

    changed = False
    backups: dict[pathlib.PurePosixPath, bytes | None] = {}
    touched = sorted(current | set(desired), key=str)
    for relative in touched:
        destination = system_config / str(relative)
        backups[relative] = destination.read_bytes() if destination.exists() else None

    try:
        for relative in sorted(current - set(desired), key=str):
            (system_config / str(relative)).unlink()
            changed = True
        for relative, (source, expected_hash) in sorted(desired.items(), key=lambda item: str(item[0])):
            destination = system_config / str(relative)
            try:
                same = destination.is_file() and _sha256(destination) == expected_hash
            except OSError:
                same = False
            if same:
                continue
            if destination.exists() and not _OWNED_FILE.fullmatch(destination.name):
                raise FirewalldReconcileError(f"refusing to overwrite non-V2 firewalld file {destination}")
            _atomic_copy(source, destination)
            changed = True
        if not changed:
            return {"ok": True, "changed": False, "files": sorted(str(item) for item in desired)}

        for directory_name in ("zones", "policies"):
            _fsync(system_config / directory_name)

        checked = _run([firewall_offline_cmd, f"--system-config={system_config}", "--check-config"])
        if checked.returncode != 0:
            detail = (checked.stderr or checked.stdout).strip()[:4000]
            raise FirewalldReconcileError(f"combined firewalld configuration is invalid: {detail}")
        reloaded = _run([firewall_cmd, "--reload"])
        if reloaded.returncode != 0:
            detail = (reloaded.stderr or reloaded.stdout).strip()[:4000]
            raise FirewalldReconcileError(f"firewalld reload failed: {detail}")
    except Exception as original:
        rollback_error: Exception | None = None
        try:
            for relative, previous in backups.items():
                destination = system_config / str(relative)
                if previous is None:
                    destination.unlink(missing_ok=True)
                    continue
                fd, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.rollback.", dir=destination.parent)
                temp = pathlib.Path(raw_temp)
                replaced = False
                try:
                    with os.fdopen(fd, "wb") as writer:
                        writer.write(previous)
                        writer.flush()
                        os.fsync(writer.fileno())
                    os.chmod(temp, 0o600)
                    os.replace(temp, destination)
                    replaced = True
                finally:
                    if not replaced:
                        temp.unlink(missing_ok=True)
            for directory_name in ("zones", "policies"):
                _fsync(system_config / directory_name)
            rollback = _run([firewall_cmd, "--reload"])
            if rollback.returncode != 0:
                raise FirewalldReconcileError((rollback.stderr or rollback.stdout).strip()[:4000])
        except Exception as exc:  # noqa: BLE001
            rollback_error = exc
        if rollback_error is not None:
            raise FirewalldReconcileError(
                f"firewalld activation failed and rollback reload also failed: original={original}; rollback={rollback_error}"
            ) from original
        if isinstance(original, FirewalldReconcileError):
            raise
        raise FirewalldReconcileError(str(original)) from original

    return {"ok": True, "changed": True, "files": sorted(str(item) for item in desired)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--projection-root", required=True)
    parser.add_argument("--system-config", required=True)
    parser.add_argument("--firewall-cmd", default="firewall-cmd")
    parser.add_argument("--firewall-offline-cmd", default="firewall-offline-cmd")
    args = parser.parse_args(argv)
    try:
        result = reconcile(
            manifest_path=pathlib.Path(args.manifest),
            projection_root=pathlib.Path(args.projection_root),
            system_config=pathlib.Path(args.system_config),
            firewall_cmd=args.firewall_cmd,
            firewall_offline_cmd=args.firewall_offline_cmd,
        )
    except FirewalldReconcileError as exc:
        print(f"nas-v2-firewalld-reconcile: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
