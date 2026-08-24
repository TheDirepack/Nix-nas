#!/usr/bin/env python3
"""Stateless activation of the V2-owned firewalld projection.

Nix NAS owns the appliance firewall and the ``nv2*`` namespace completely.
Desired-state history lives in Git, so this reconciler does not maintain a
second rollback database, acknowledgement token, or copies of previous XML.
A generic systemd rollback guard restores the last-applied desired state if the
whole reconciliation transaction does not complete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any, Sequence

_OWNED_FILE = re.compile(r"^nv2[zhwlrima][0-9a-f]{12}\.xml$")


class FirewalldReconcileError(RuntimeError):
    """Raised when the projected firewall cannot be activated and verified."""


def _run(command: Sequence[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewalldReconcileError(f"unable to execute {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise FirewalldReconcileError(f"command failed ({result.returncode}): {' '.join(command)}: {detail}")
    return result


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_target(raw: str) -> pathlib.PurePosixPath:
    target = pathlib.PurePosixPath(raw)
    if len(target.parts) != 2 or target.parts[0] not in {"zones", "policies"}:
        raise FirewalldReconcileError(f"unsafe firewalld target {raw!r}")
    if not _OWNED_FILE.fullmatch(target.name):
        raise FirewalldReconcileError(f"firewalld target {raw!r} is outside the V2 ownership namespace")
    return target


def _read_projection(
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
) -> dict[pathlib.PurePosixPath, pathlib.Path]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FirewalldReconcileError(f"unable to read firewalld manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1 or not isinstance(manifest.get("files"), list):
        raise FirewalldReconcileError("firewalld projection manifest is invalid")

    desired: dict[pathlib.PurePosixPath, pathlib.Path] = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("target"), str) or not isinstance(entry.get("sha256"), str):
            raise FirewalldReconcileError("firewalld manifest file entry is invalid")
        target = _safe_target(entry["target"])
        source = projection_root / str(target)
        try:
            source.relative_to(projection_root)
        except ValueError as exc:
            raise FirewalldReconcileError(f"projection source escapes root: {source}") from exc
        if not source.is_file():
            raise FirewalldReconcileError(f"projected firewalld file is missing: {source}")
        if _sha256(source) != entry["sha256"]:
            raise FirewalldReconcileError(f"projected firewalld file changed after validation: {source}")
        if target in desired:
            raise FirewalldReconcileError(f"duplicate firewalld projection target: {target}")
        desired[target] = source
    return desired


def _atomic_copy(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temp = pathlib.Path(raw_temp)
    replaced = False
    try:
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            while chunk := reader.read(1024 * 1024):
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, destination)
        replaced = True
    finally:
        if not replaced:
            temp.unlink(missing_ok=True)


def _owned_files(system_config: pathlib.Path) -> set[pathlib.PurePosixPath]:
    current: set[pathlib.PurePosixPath] = set()
    for kind in ("zones", "policies"):
        directory = system_config / kind
        directory.mkdir(parents=True, exist_ok=True)
        for path in directory.iterdir():
            if path.is_file() and _OWNED_FILE.fullmatch(path.name):
                current.add(pathlib.PurePosixPath(kind) / path.name)
    return current


def _verify_runtime(
    *,
    desired: dict[pathlib.PurePosixPath, pathlib.Path],
    firewall_cmd: str,
) -> None:
    _run([firewall_cmd, "--state"])
    zones = set(_run([firewall_cmd, "--get-zones"]).stdout.split())
    policies = set(_run([firewall_cmd, "--get-policies"]).stdout.split())
    expected_zones = {target.stem for target in desired if target.parts[0] == "zones"}
    expected_policies = {target.stem for target in desired if target.parts[0] == "policies"}
    missing_zones = sorted(expected_zones - zones)
    missing_policies = sorted(expected_policies - policies)
    if missing_zones or missing_policies:
        detail: list[str] = []
        if missing_zones:
            detail.append(f"zones={','.join(missing_zones)}")
        if missing_policies:
            detail.append(f"policies={','.join(missing_policies)}")
        raise FirewalldReconcileError("firewalld reload omitted projected objects: " + " ".join(detail))


def reconcile(
    *,
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
    system_config: pathlib.Path,
    firewall_cmd: str = "firewall-cmd",
) -> dict[str, Any]:
    """Replace the complete V2 namespace, reload firewalld, and verify it."""
    desired = _read_projection(manifest_path, projection_root)
    current = _owned_files(system_config)
    changed = False

    for target in sorted(current - set(desired), key=str):
        (system_config / str(target)).unlink(missing_ok=True)
        changed = True
    for target, source in sorted(desired.items(), key=lambda item: str(item[0])):
        destination = system_config / str(target)
        try:
            same = destination.is_file() and _sha256(destination) == _sha256(source)
        except OSError:
            same = False
        if same:
            continue
        _atomic_copy(source, destination)
        changed = True

    # Nix NAS owns firewalld's system config.  A normal reload is therefore the
    # canonical runtime reconciliation: it discards runtime drift and loads the
    # exact permanent configuration we just projected while preserving tracked
    # connections.  The outer guarded-apply transaction handles crash rollback.
    _run([firewall_cmd, "--check-config"])
    _run([firewall_cmd, "--reload"])
    _verify_runtime(desired=desired, firewall_cmd=firewall_cmd)
    return {
        "ok": True,
        "changed": changed,
        "files": sorted(str(target) for target in desired),
        "runtimeVerified": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Activate and verify the complete V2-owned firewalld projection")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--projection-root", required=True)
    parser.add_argument("--system-config", required=True)
    parser.add_argument("--firewall-cmd", default="firewall-cmd")
    args = parser.parse_args(argv)
    try:
        result = reconcile(
            manifest_path=pathlib.Path(args.manifest),
            projection_root=pathlib.Path(args.projection_root),
            system_config=pathlib.Path(args.system_config),
            firewall_cmd=args.firewall_cmd,
        )
    except FirewalldReconcileError as exc:
        print(f"nas-v2-firewalld-reconcile: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = ["FirewalldReconcileError", "reconcile"]


if __name__ == "__main__":
    raise SystemExit(main())
