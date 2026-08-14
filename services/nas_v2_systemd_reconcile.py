#!/usr/bin/env python3
"""Reconcile staged V2 systemd and Quadlet links, then exit."""

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
from typing import Any


class SystemdReconcileError(RuntimeError):
    """Raised when staged V2 systemd state cannot be reconciled safely."""


_UNIT = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|timer|target|path)$")
_DROPIN = re.compile(r"^([A-Za-z0-9_.@:-]+\.(?:service|timer|target))\.d/50-nas-v2\.conf$")
_QUADLET_CONTAINER = re.compile(r"^nas-v2-([a-z][a-z0-9-]{0,63})\.container$")
_QUADLET_NETWORK = re.compile(r"^nas-v2-net-([a-z][a-z0-9-]{0,63})\.network$")
_QUADLET_SESSION_NETWORK = re.compile(r"^nas-v2-snet-([a-z][a-z0-9-]{0,63})\.network$")


def _read_json(path: pathlib.Path, *, required: bool) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if not required:
            return {}
        raise SystemdReconcileError(f"required state file does not exist: {path}") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemdReconcileError(f"unable to read state file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemdReconcileError(f"state file {path} must contain an object")
    return value


def _safe_target(root: pathlib.Path, relative: str) -> tuple[pathlib.Path, str]:
    match = _DROPIN.fullmatch(relative)
    if match:
        return root / relative, match.group(1)
    if _UNIT.fullmatch(relative):
        return root / relative, relative
    raise SystemdReconcileError(f"unsafe generated systemd target {relative!r}")


def _safe_quadlet_target(root: pathlib.Path, relative: str) -> tuple[pathlib.Path, str]:
    container = _QUADLET_CONTAINER.fullmatch(relative)
    if container:
        return root / relative, f"nas-v2-{container.group(1)}.service"
    network = _QUADLET_NETWORK.fullmatch(relative)
    if network:
        return root / relative, f"nas-v2-{network.group(1)}.service"
    session_network = _QUADLET_SESSION_NETWORK.fullmatch(relative)
    if session_network:
        return root / relative, f"nas-v2-session-{session_network.group(1)}.target"
    raise SystemdReconcileError(f"unsafe generated Quadlet target {relative!r}")


def _source_under(root: pathlib.Path, value: str) -> pathlib.Path:
    source = pathlib.Path(value)
    try:
        resolved = source.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise SystemdReconcileError(f"generated source escapes projection root: {value}") from exc
    if not resolved.is_file():
        raise SystemdReconcileError(f"generated source is not a file: {value}")
    return resolved


def _hash_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_systemctl(systemctl: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [systemctl, *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:2000]
        raise SystemdReconcileError(f"systemctl {' '.join(args)} failed: {detail}")
    return result


def _atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = pathlib.Path(raw_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temp.unlink(missing_ok=True)


def _unlink_owned(target: pathlib.Path, projection_root: pathlib.Path) -> None:
    if not target.is_symlink():
        if target.exists():
            raise SystemdReconcileError(f"refusing to remove non-V2 generated file {target}")
        return
    raw = os.readlink(target)
    linked = pathlib.Path(raw)
    if not linked.is_absolute():
        linked = target.parent / linked
    try:
        linked.resolve(strict=False).relative_to(projection_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise SystemdReconcileError(f"refusing to remove non-V2 generated symlink {target}") from exc
    target.unlink()


def _link_matches(target: pathlib.Path, source: pathlib.Path) -> bool:
    if not target.is_symlink():
        return False
    raw = os.readlink(target)
    current = pathlib.Path(raw)
    if not current.is_absolute():
        current = target.parent / current
    return current.resolve(strict=False) == source


def _ensure_link(target: pathlib.Path, source: pathlib.Path, projection_root: pathlib.Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        if _link_matches(target, source):
            return
        _unlink_owned(target, projection_root)
    elif target.exists():
        raise SystemdReconcileError(f"refusing to overwrite non-V2 generated file {target}")
    target.symlink_to(source)


def _parse_links(
    manifest: dict[str, Any],
    *,
    key: str,
    projection_root: pathlib.Path,
    runtime_root: pathlib.Path,
    quadlet: bool,
) -> tuple[dict[str, pathlib.Path], dict[str, str], dict[str, str], bool]:
    raw_links = manifest.get(key, [])
    if not isinstance(raw_links, list):
        raise SystemdReconcileError(f"systemd projection manifest {key} must be an array")
    links: dict[str, pathlib.Path] = {}
    affected_units: dict[str, str] = {}
    hashes: dict[str, str] = {}
    drift = False
    for item in raw_links:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("target"), str)
            or not isinstance(item.get("source"), str)
        ):
            raise SystemdReconcileError(f"invalid systemd projection {key} entry")
        target_rel = item["target"]
        if quadlet:
            target_path, affected = _safe_quadlet_target(runtime_root, target_rel)
        else:
            target_path, affected = _safe_target(runtime_root, target_rel)
        source = _source_under(projection_root, item["source"])
        if target_rel in links:
            raise SystemdReconcileError(f"duplicate generated target {target_rel!r}")
        links[target_rel] = source
        affected_units[target_rel] = affected
        hashes[target_rel] = _hash_file(source)
        if not _link_matches(target_path, source):
            drift = True
    return links, affected_units, hashes, drift


def reconcile(
    *,
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
    systemd_runtime_dir: pathlib.Path,
    quadlet_runtime_dir: pathlib.Path,
    state_path: pathlib.Path,
    systemctl: str,
) -> dict[str, Any]:
    manifest = _read_json(manifest_path, required=True)
    previous = _read_json(state_path, required=False)
    if manifest.get("schemaVersion") != 1:
        raise SystemdReconcileError("unsupported systemd projection manifest version")

    links, affected_units, current_hashes, link_drift = _parse_links(
        manifest,
        key="links",
        projection_root=projection_root,
        runtime_root=systemd_runtime_dir,
        quadlet=False,
    )
    quadlet_links, quadlet_affected, current_quadlet_hashes, quadlet_drift = _parse_links(
        manifest,
        key="quadletLinks",
        projection_root=projection_root,
        runtime_root=quadlet_runtime_dir,
        quadlet=True,
    )

    def string_set(key: str, source: dict[str, Any]) -> set[str]:
        value = source.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) and _UNIT.fullmatch(item) for item in value):
            raise SystemdReconcileError(f"manifest field {key} must contain safe unit names")
        return set(value)

    owned = string_set("ownedUnits", manifest)
    start = string_set("startUnits", manifest)
    stop = string_set("stopUnits", manifest)
    if not start <= owned or not stop <= owned:
        raise SystemdReconcileError("startUnits and stopUnits must be owned units")

    previous_owned = string_set("ownedUnits", previous) if previous else set()
    previous_start = string_set("startUnits", previous) if previous else set()
    previous_stop = string_set("stopUnits", previous) if previous else set()
    previous_links_raw = previous.get("links", {}) if previous else {}
    previous_hashes = previous.get("linkHashes", {}) if previous else {}
    previous_quadlet_links_raw = previous.get("quadletLinks", {}) if previous else {}
    previous_quadlet_hashes = previous.get("quadletHashes", {}) if previous else {}
    previous_fingerprints = previous.get("fingerprints", {}) if previous else {}
    if not all(
        isinstance(value, dict)
        for value in (
            previous_links_raw,
            previous_hashes,
            previous_quadlet_links_raw,
            previous_quadlet_hashes,
            previous_fingerprints,
        )
    ):
        raise SystemdReconcileError("previous systemd reconcile state is malformed")

    fingerprints = manifest.get("fingerprints", {})
    if not isinstance(fingerprints, dict):
        raise SystemdReconcileError("manifest fingerprints must be an object")
    for unit, digest in fingerprints.items():
        if not isinstance(unit, str) or not _UNIT.fullmatch(unit) or not isinstance(digest, str):
            raise SystemdReconcileError("manifest contains an invalid runtime fingerprint")

    current_links = {target: str(source) for target, source in sorted(links.items())}
    current_quadlet_links = {target: str(source) for target, source in sorted(quadlet_links.items())}
    stale_links = set(previous_links_raw) - set(links)
    stale_quadlet_links = set(previous_quadlet_links_raw) - set(quadlet_links)
    topology_changed = (
        current_links != previous_links_raw
        or current_hashes != previous_hashes
        or current_quadlet_links != previous_quadlet_links_raw
        or current_quadlet_hashes != previous_quadlet_hashes
        or bool(stale_links)
        or bool(stale_quadlet_links)
        or link_drift
        or quadlet_drift
    )
    lifecycle_changed = owned != previous_owned or start != previous_start or stop != previous_stop
    fingerprint_changed = fingerprints != previous_fingerprints

    if previous and not topology_changed and not lifecycle_changed and not fingerprint_changed:
        return {"stopped": [], "changed": [], "started": [], "noop": True}

    units_to_stop = (previous_owned - owned) | (previous_start - start) | stop
    changed_units: set[str] = set()
    for target_rel, digest in current_hashes.items():
        if previous_hashes.get(target_rel) != digest:
            changed_units.add(affected_units[target_rel])
    for target_rel, digest in current_quadlet_hashes.items():
        if previous_quadlet_hashes.get(target_rel) != digest:
            changed_units.add(quadlet_affected[target_rel])
    for unit, digest in fingerprints.items():
        if previous_fingerprints.get(unit) != digest:
            changed_units.add(unit)

    def _rollback_projection() -> None:
        for target_rel, source in links.items():
            if target_rel not in previous_links_raw:
                target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
                if target_path.is_symlink():
                    _unlink_owned(target_path, projection_root)
                    if target_path.parent != systemd_runtime_dir:
                        try:
                            target_path.parent.rmdir()
                        except OSError:
                            pass
            else:
                prev_source_str = previous_links_raw[target_rel]
                prev_source = pathlib.Path(prev_source_str)
                target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
                if not _link_matches(target_path, prev_source):
                    if target_path.is_symlink() or not target_path.exists():
                        _unlink_owned(target_path, projection_root)
                    else:
                        raise SystemdReconcileError(f"refusing to remove non-V2 generated file {target_path}")
                    if prev_source.is_file():
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        target_path.symlink_to(prev_source)
        for target_rel in sorted(stale_links):
            prev_source_str = previous_links_raw[target_rel]
            prev_source = pathlib.Path(prev_source_str)
            target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
            if not _link_matches(target_path, prev_source):
                if prev_source.is_file():
                    _ensure_link(target_path, prev_source, projection_root)
                elif target_path.is_symlink():
                    _unlink_owned(target_path, projection_root)
        for target_rel, source in quadlet_links.items():
            if target_rel not in previous_quadlet_links_raw:
                target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
                if target_path.is_symlink():
                    _unlink_owned(target_path, projection_root)
            else:
                prev_source_str = previous_quadlet_links_raw[target_rel]
                prev_source = pathlib.Path(prev_source_str)
                target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
                if not _link_matches(target_path, prev_source):
                    if target_path.is_symlink() or not target_path.exists():
                        _unlink_owned(target_path, projection_root)
                    else:
                        raise SystemdReconcileError(f"refusing to remove non-V2 generated file {target_path}")
                    if prev_source.is_file():
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        target_path.symlink_to(prev_source)
        for target_rel in sorted(stale_quadlet_links):
            prev_source_str = previous_quadlet_links_raw[target_rel]
            prev_source = pathlib.Path(prev_source_str)
            target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
            if not _link_matches(target_path, prev_source):
                if prev_source.is_file():
                    _ensure_link(target_path, prev_source, projection_root)
                elif target_path.is_symlink():
                    _unlink_owned(target_path, projection_root)
        if topology_changed:
            _run_systemctl(systemctl, "daemon-reload")

    try:
        for unit in sorted(units_to_stop):
            _run_systemctl(systemctl, "stop", unit)

        for target_rel, source in links.items():
            target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
            _ensure_link(target_path, source, projection_root)

        for target_rel, source in quadlet_links.items():
            target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
            _ensure_link(target_path, source, projection_root)

        for target_rel in sorted(stale_links):
            target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
            _unlink_owned(target_path, projection_root)
            if target_path.parent != systemd_runtime_dir:
                try:
                    target_path.parent.rmdir()
                except OSError:
                    pass

        for target_rel in sorted(stale_quadlet_links):
            target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
            _unlink_owned(target_path, projection_root)

        if topology_changed:
            _run_systemctl(systemctl, "daemon-reload")

        restarted: set[str] = set()
        for unit in sorted(changed_units & owned):
            if unit in start:
                _run_systemctl(systemctl, "restart", unit)
                restarted.add(unit)
            else:
                _run_systemctl(systemctl, "try-restart", unit, check=False)

        units_to_start = (start - previous_start) - restarted
        for unit in sorted(units_to_start):
            _run_systemctl(systemctl, "start", unit)

        state = {
            "schemaVersion": 1,
            "links": current_links,
            "linkHashes": current_hashes,
            "quadletLinks": current_quadlet_links,
            "quadletHashes": current_quadlet_hashes,
            "ownedUnits": sorted(owned),
            "startUnits": sorted(start),
            "stopUnits": sorted(stop),
            "fingerprints": fingerprints,
        }
        _atomic_json(state_path, state)
        return {
            "stopped": sorted(units_to_stop),
            "changed": sorted(changed_units),
            "started": sorted(units_to_start | restarted),
            "noop": False,
        }
    except Exception as exc:
        rollback_error: Exception | None = None
        try:
            _rollback_projection()
        except Exception as r_exc:  # noqa: BLE001
            rollback_error = r_exc
        if rollback_error is not None:
            raise SystemdReconcileError(
                f"systemd reconcile failed: {exc}; rollback failed: {rollback_error}; manual recovery required"
            ) from exc
        if isinstance(exc, SystemdReconcileError):
            raise
        raise SystemdReconcileError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reconcile staged Managed Services V2 systemd units")
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--projection-root", type=pathlib.Path, required=True)
    parser.add_argument("--systemd-runtime-dir", type=pathlib.Path, default=pathlib.Path("/run/systemd/system"))
    parser.add_argument(
        "--quadlet-runtime-dir",
        type=pathlib.Path,
        default=pathlib.Path("/run/containers/systemd"),
    )
    parser.add_argument("--state", type=pathlib.Path, default=pathlib.Path("/run/nas-control/systemd-reconciled.json"))
    parser.add_argument("--systemctl", default="systemctl")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = reconcile(
            manifest_path=args.manifest,
            projection_root=args.projection_root,
            systemd_runtime_dir=args.systemd_runtime_dir,
            quadlet_runtime_dir=args.quadlet_runtime_dir,
            state_path=args.state,
            systemctl=args.systemctl,
        )
    except SystemdReconcileError as exc:
        print(f"nas-v2-systemd-reconcile: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
