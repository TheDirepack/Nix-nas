#!/usr/bin/env python3
"""Reconcile V2-owned systemd/Quadlet runtime links, then exit.

Generated projection files are immutable generation artifacts. This reconciler
therefore never copies or rewrites projection bytes. It snapshots only the
live runtime symlink topology and unit active state before mutation; a failed
activation restores those native runtime links/states while the outer guarded
V2 transaction selects the previous desired-state generation.
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
from typing import Any


class SystemdReconcileError(RuntimeError):
    """Raised when staged V2 systemd state cannot be reconciled safely."""


_UNIT = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|timer|target|path|socket)$")
_DROPIN = re.compile(r"^([A-Za-z0-9_.@:-]+\.(?:service|timer|target))\.d/50-nas-v2\.conf$")
_QUADLET_DIRECT_CONTAINER = re.compile(r"^nas-v2-([a-z][a-z0-9-]{0,63})\.container$")
_QUADLET_DIRECT_NETWORK = re.compile(r"^nas-v2-net-([a-z][a-z0-9-]{0,63})\.network$")
_QUADLET_SESSION_NETWORK = re.compile(r"^nas-v2-snet-([a-z][a-z0-9-]{0,63})\.network$")
_QUADLET = re.compile(r"^nas-v2-[A-Za-z0-9_.@:-]+\.(?:container|pod|network|volume|kube|image|build)$")


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
    direct_container = _QUADLET_DIRECT_CONTAINER.fullmatch(relative)
    if direct_container:
        return root / relative, f"nas-v2-{direct_container.group(1)}.service"
    direct_network = _QUADLET_DIRECT_NETWORK.fullmatch(relative)
    if direct_network:
        return root / relative, f"nas-v2-{direct_network.group(1)}.service"
    session_network = _QUADLET_SESSION_NETWORK.fullmatch(relative)
    if session_network:
        return root / relative, f"nas-v2-session-{session_network.group(1)}.target"
    if _QUADLET.fullmatch(relative) is None:
        raise SystemdReconcileError(f"unsafe generated Quadlet target {relative!r}")
    path = pathlib.Path(relative)
    name = path.stem
    suffix = path.suffix
    if suffix == ".container":
        affected = f"{name}.service"
    elif suffix == ".network":
        affected = f"{name}-network.service"
    elif suffix == ".pod":
        affected = f"{name}-pod.service"
    elif suffix == ".volume":
        affected = f"{name}-volume.service"
    elif suffix == ".image":
        affected = f"{name}-image.service"
    elif suffix == ".build":
        affected = f"{name}-build.service"
    else:
        affected = f"{name}.service"
    return root / relative, affected


def _hash_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(directory: pathlib.Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
        _fsync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def _projection_roots(projection_root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    """Return systemd generation roots allowed to back V2 runtime symlinks."""
    try:
        current = projection_root.resolve(strict=True)
    except OSError as exc:
        raise SystemdReconcileError(f"projection root is unavailable: {projection_root}: {exc}") from exc
    roots = [current]
    generations = projection_root.parent / "generations"
    try:
        if generations.is_dir() and not generations.is_symlink():
            for generation in generations.iterdir():
                candidate = generation / "systemd"
                if candidate.is_dir() and not candidate.is_symlink():
                    resolved = candidate.resolve(strict=True)
                    if resolved not in roots:
                        roots.append(resolved)
    except OSError:
        pass
    return tuple(roots)


def _is_under(path: pathlib.Path, roots: tuple[pathlib.Path, ...], *, strict: bool) -> pathlib.Path:
    try:
        resolved = path.resolve(strict=strict)
    except OSError as exc:
        raise SystemdReconcileError(f"unable to resolve generated path {path}: {exc}") from exc
    for root in roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise SystemdReconcileError(f"generated source is outside V2 systemd generation roots: {path}")


def _source_under_current(projection_root: pathlib.Path, value: str) -> pathlib.Path:
    source = pathlib.Path(value)
    if not source.is_absolute():
        raise SystemdReconcileError(f"generated source is not absolute: {value}")
    current = projection_root.resolve(strict=True)
    resolved = _is_under(source, (current,), strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise SystemdReconcileError(f"generated source is not a regular file: {value}")
    return resolved


def _read_owned_link(target: pathlib.Path, projection_roots: tuple[pathlib.Path, ...]) -> pathlib.Path | None:
    if target.is_symlink():
        raw = pathlib.Path(os.readlink(target))
        linked = raw if raw.is_absolute() else target.parent / raw
        resolved = _is_under(linked, projection_roots, strict=True)
        if not resolved.is_file():
            raise SystemdReconcileError(f"V2 runtime link does not target a generated file: {target}")
        return resolved
    if target.exists():
        raise SystemdReconcileError(f"refusing to overwrite non-V2 generated file {target}")
    return None


def _set_link(
    target: pathlib.Path,
    source: pathlib.Path | None,
    *,
    projection_roots: tuple[pathlib.Path, ...],
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    current = _read_owned_link(target, projection_roots)
    if source is None:
        if current is not None:
            target.unlink()
        return
    resolved_source = _is_under(source, projection_roots, strict=True)
    if current == resolved_source:
        return
    if current is not None:
        target.unlink()
    target.symlink_to(resolved_source)


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
    roots = _projection_roots(projection_root)
    for item in raw_links:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("target"), str)
            or not isinstance(item.get("source"), str)
        ):
            raise SystemdReconcileError(f"invalid systemd projection {key} entry")
        target_rel = item["target"]
        target_path, affected = (
            _safe_quadlet_target(runtime_root, target_rel) if quadlet else _safe_target(runtime_root, target_rel)
        )
        source = _source_under_current(projection_root, item["source"])
        if target_rel in links:
            raise SystemdReconcileError(f"duplicate generated target {target_rel!r}")
        links[target_rel] = source
        affected_units[target_rel] = affected
        hashes[target_rel] = _hash_file(source)
        if _read_owned_link(target_path, roots) != source:
            drift = True
    return links, affected_units, hashes, drift


def _run_systemctl(systemctl: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [systemctl, *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemdReconcileError(f"unable to execute systemctl {' '.join(args)}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:2000]
        raise SystemdReconcileError(f"systemctl {' '.join(args)} failed: {detail}")
    return result


def _string_set(key: str, source: dict[str, Any]) -> set[str]:
    value = source.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and _UNIT.fullmatch(item) for item in value):
        raise SystemdReconcileError(f"manifest field {key} must contain safe unit names")
    return set(value)


def _state_link_keys(key: str, state: dict[str, Any]) -> set[str]:
    value = state.get(key, {})
    if not isinstance(value, dict) or not all(isinstance(name, str) for name in value):
        raise SystemdReconcileError(f"previous systemd reconcile field {key} is malformed")
    return set(value)


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

    owned = _string_set("ownedUnits", manifest)
    start = _string_set("startUnits", manifest)
    stop = _string_set("stopUnits", manifest)
    if not start <= owned or not stop <= owned:
        raise SystemdReconcileError("startUnits and stopUnits must be owned units")

    previous_owned = _string_set("ownedUnits", previous) if previous else set()
    previous_start = _string_set("startUnits", previous) if previous else set()
    previous_stop = _string_set("stopUnits", previous) if previous else set()
    previous_links_raw = previous.get("links", {}) if previous else {}
    previous_quadlet_links_raw = previous.get("quadletLinks", {}) if previous else {}
    previous_hashes = previous.get("linkHashes", {}) if previous else {}
    previous_quadlet_hashes = previous.get("quadletHashes", {}) if previous else {}
    previous_fingerprints = previous.get("fingerprints", {}) if previous else {}
    if not all(
        isinstance(value, dict)
        for value in (
            previous_links_raw,
            previous_quadlet_links_raw,
            previous_hashes,
            previous_quadlet_hashes,
            previous_fingerprints,
        )
    ):
        raise SystemdReconcileError("previous systemd reconcile state is malformed")

    previous_link_keys = _state_link_keys("links", previous) if previous else set()
    previous_quadlet_link_keys = _state_link_keys("quadletLinks", previous) if previous else set()
    current_links = {target: str(source) for target, source in sorted(links.items())}
    current_quadlet_links = {target: str(source) for target, source in sorted(quadlet_links.items())}
    stale_links = previous_link_keys - set(links)
    stale_quadlet_links = previous_quadlet_link_keys - set(quadlet_links)

    fingerprints = manifest.get("fingerprints", {})
    if not isinstance(fingerprints, dict):
        raise SystemdReconcileError("manifest fingerprints must be an object")
    for unit, digest in fingerprints.items():
        if not isinstance(unit, str) or _UNIT.fullmatch(unit) is None or not isinstance(digest, str):
            raise SystemdReconcileError("manifest contains an invalid runtime fingerprint")

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

    def is_active(unit: str) -> bool | None:
        try:
            result = _run_systemctl(systemctl, "is-active", unit, check=False)
        except SystemdReconcileError:
            return None
        return result.stdout.strip() == "active"

    all_units = previous_owned | owned | previous_start | start | stop | units_to_stop | changed_units
    active_snapshot = {unit: is_active(unit) for unit in sorted(all_units)}

    roots = _projection_roots(projection_root)
    systemd_targets = set(links) | stale_links
    quadlet_targets = set(quadlet_links) | stale_quadlet_links
    live_systemd: dict[str, pathlib.Path | None] = {}
    live_quadlet: dict[str, pathlib.Path | None] = {}
    for target_rel in sorted(systemd_targets):
        target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
        live_systemd[target_rel] = _read_owned_link(target_path, roots)
    for target_rel in sorted(quadlet_targets):
        target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
        live_quadlet[target_rel] = _read_owned_link(target_path, roots)

    def rollback_links() -> None:
        for target_rel, source in live_systemd.items():
            target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
            _set_link(target_path, source, projection_roots=roots)
            if source is None and target_path.parent != systemd_runtime_dir:
                try:
                    target_path.parent.rmdir()
                except OSError:
                    pass
        for target_rel, source in live_quadlet.items():
            target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
            _set_link(target_path, source, projection_roots=roots)
        if topology_changed:
            _run_systemctl(systemctl, "daemon-reload")

    def rollback_active_state() -> None:
        for unit, was_active in active_snapshot.items():
            if was_active is None:
                continue
            now_active = is_active(unit)
            if now_active is None or now_active == was_active:
                continue
            try:
                _run_systemctl(systemctl, "start" if was_active else "stop", unit)
            except SystemdReconcileError:
                continue

    try:
        for unit in sorted(units_to_stop):
            _run_systemctl(systemctl, "stop", unit)

        for target_rel, source in links.items():
            target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
            _set_link(target_path, source, projection_roots=roots)
        for target_rel, source in quadlet_links.items():
            target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
            _set_link(target_path, source, projection_roots=roots)
        for target_rel in sorted(stale_links):
            target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
            _set_link(target_path, None, projection_roots=roots)
            if target_path.parent != systemd_runtime_dir:
                try:
                    target_path.parent.rmdir()
                except OSError:
                    pass
        for target_rel in sorted(stale_quadlet_links):
            target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
            _set_link(target_path, None, projection_roots=roots)

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
            rollback_links()
            rollback_active_state()
        except Exception as rollback_exc:  # noqa: BLE001
            rollback_error = rollback_exc
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
    parser.add_argument("--quadlet-runtime-dir", type=pathlib.Path, default=pathlib.Path("/run/containers/systemd"))
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
