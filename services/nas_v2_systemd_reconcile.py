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
import contextlib
import configparser
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any, Mapping

from nas_common import fsync_directory as _fsync_directory


class SystemdReconcileError(RuntimeError):
    """Raised when staged V2 systemd state cannot be reconciled safely."""


_UNIT = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|timer|target|path|socket)$")
_DROPIN = re.compile(r"^([A-Za-z0-9_.@:-]+\.(?:service|timer|target))\.d/50-nas-v2\.conf$")
_QUADLET_DIRECT_CONTAINER = re.compile(r"^nas-v2-([a-z][a-z0-9-]{0,63})\.container$")
_QUADLET_DIRECT_NETWORK = re.compile(r"^nas-v2-net-([a-z][a-z0-9-]{0,63})\.network$")
_QUADLET_SESSION_NETWORK = re.compile(r"^nas-v2-snet-([a-z][a-z0-9-]{0,63})\.network$")
_QUADLET = re.compile(r"^nas-v2-[A-Za-z0-9_.@:-]+\.(?:container|pod|network|volume|kube|image|build)$")
_SYSTEMCTL_TIMEOUT_SECONDS = 180
_TRANSITIONAL_UNIT_STATES = frozenset({"activating", "deactivating", "reloading", "refreshing"})
_UNIT_QUERY_STATES = {
    0: frozenset({"active", "reloading", "refreshing"}),
    3: frozenset({"inactive", "failed", "activating", "deactivating", "maintenance"}),
    4: frozenset({"unknown", "inactive"}),
}
# systemctl stop exits non-zero for units the manager cannot resolve; those
# units cannot be running, so the reconcile's stop intent is already satisfied.
_ALREADY_STOPPED_STATUSES = ("not found", "could not be found", "not loaded", "masked")


def _read_json(path: pathlib.Path, *, required: bool) -> tuple[dict[str, Any], bytes | None]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        if not required:
            return {}, None
        raise SystemdReconcileError(f"required state file does not exist: {path}") from None
    except (OSError, ValueError) as exc:
        raise SystemdReconcileError(f"unable to read state file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemdReconcileError(f"state file {path} must contain an object")
    return value, raw


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


def _atomic_bytes(path: pathlib.Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = pathlib.Path(raw_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        _fsync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def _atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    _atomic_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


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
        if not linked.exists():
            # Dangling symlink: the runtime link exists but its target is
            # missing. Treat as drift so the reconcile loop repairs it rather
            # than failing the whole activation.
            return None
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
    if target.is_symlink() and not target.exists():
        target.unlink()
        current = None
    else:
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


def _update_links(
    runtime_root: pathlib.Path,
    links: Mapping[str, pathlib.Path | None],
    projection_roots: tuple[pathlib.Path, ...],
    *,
    quadlet: bool = False,
) -> None:
    """Use ownership-checked targets for activation, retirement, and rollback; retain nonempty drop-in dirs."""
    safe_target = _safe_quadlet_target if quadlet else _safe_target
    for relative, source in links.items():
        target, _ = safe_target(runtime_root, relative)
        _set_link(target, source, projection_roots=projection_roots)
        if source is None and target.parent != runtime_root:
            with contextlib.suppress(OSError):
                target.parent.rmdir()


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


def _run_systemctl(
    systemctl: str, *args: str, check: bool = True, timeout_seconds: int = _SYSTEMCTL_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [systemctl, *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
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


def _discover_systemd_links(runtime_root: pathlib.Path) -> set[str]:
    """Find links owned by V2 even if a killed reconcile missed its state write."""
    discovered: set[str] = set()
    try:
        entries = list(runtime_root.iterdir())
    except FileNotFoundError:
        return discovered
    except OSError as exc:
        raise SystemdReconcileError(f"unable to inspect systemd runtime directory {runtime_root}: {exc}") from exc
    for entry in entries:
        if entry.is_symlink():
            if entry.name.startswith("nas-v2-") and _UNIT.fullmatch(entry.name):
                discovered.add(entry.name)
            continue
        if not entry.is_dir():
            continue
        relative = f"{entry.name}/50-nas-v2.conf"
        if _DROPIN.fullmatch(relative) and (entry / "50-nas-v2.conf").is_symlink():
            discovered.add(relative)
    return discovered


def _discover_quadlet_links(runtime_root: pathlib.Path) -> set[str]:
    discovered: set[str] = set()
    try:
        entries = list(runtime_root.iterdir())
    except FileNotFoundError:
        return discovered
    except OSError as exc:
        raise SystemdReconcileError(f"unable to inspect Quadlet runtime directory {runtime_root}: {exc}") from exc
    for entry in entries:
        if entry.is_symlink() and entry.name.startswith("nas-v2-") and _QUADLET.fullmatch(entry.name):
            discovered.add(entry.name)
    return discovered


_SESSION_TARGET = re.compile(r"^nas-v2-session-[a-z][a-z0-9-]*\.target$")


def reconcile(
    *,
    manifest_path: pathlib.Path,
    projection_root: pathlib.Path,
    systemd_runtime_dir: pathlib.Path,
    quadlet_runtime_dir: pathlib.Path,
    state_path: pathlib.Path,
    systemctl: str,
) -> dict[str, Any]:
    """Apply native topology transactionally; lost transient sessions require manual recovery."""
    manifest, _ = _read_json(manifest_path, required=True)
    previous, previous_bytes = _read_json(state_path, required=False)
    if manifest.get("schemaVersion") != 1:
        raise SystemdReconcileError("unsupported systemd projection manifest version")
    activation_timeout = manifest.get("activationTimeoutSeconds", _SYSTEMCTL_TIMEOUT_SECONDS)
    if not isinstance(activation_timeout, int) or isinstance(activation_timeout, bool) or activation_timeout < 180:
        raise SystemdReconcileError("invalid activationTimeoutSeconds")
    previous_timeout = previous.get("activationTimeoutSeconds", _SYSTEMCTL_TIMEOUT_SECONDS)
    if not isinstance(previous_timeout, int) or isinstance(previous_timeout, bool) or previous_timeout < 180:
        raise SystemdReconcileError("invalid previous activationTimeoutSeconds")
    activation_timeout = max(activation_timeout, previous_timeout)

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
    readiness = _string_set("readinessUnits", manifest)
    stop = _string_set("stopUnits", manifest)
    if not start <= owned or not stop <= owned:
        raise SystemdReconcileError("startUnits and stopUnits must be owned units")
    if not readiness <= start:
        raise SystemdReconcileError("readinessUnits must be started owned units")
    readiness_owners = manifest.get("readinessOwners", {})
    if (
        not isinstance(readiness_owners, dict)
        or set(readiness_owners) != readiness
        or not all(isinstance(owner, str) and owner in start - readiness for owner in readiness_owners.values())
    ):
        raise SystemdReconcileError("readinessOwners must map each gate to a started owner")

    for gate, owner in readiness_owners.items():
        source = links.get(gate)
        parser = configparser.ConfigParser(interpolation=None)
        try:
            if source is None:
                raise SystemdReconcileError(f"readinessOwners gate has no generated unit: {gate}")
            parser.read_string(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, configparser.Error) as error:
            raise SystemdReconcileError(f"unable to validate readinessOwners for {gate}: {error}") from error
        if any(parser.get("Unit", key, fallback="").split() != [owner] for key in ("Requires", "After")):
            raise SystemdReconcileError(f"readinessOwners must match the declared gate owner: {gate}")

    previous_owned = _string_set("ownedUnits", previous) if previous else set()
    previous_start = _string_set("startUnits", previous) if previous else set()
    previous_readiness = _string_set("readinessUnits", previous) if previous else set()
    previous_readiness_owners = previous.get("readinessOwners", {}) if previous else {}
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
            previous_readiness_owners,
        )
    ):
        raise SystemdReconcileError("previous systemd reconcile state is malformed")
    if previous:
        _state_link_keys("readinessOwners", previous)
        if not all(isinstance(owner, str) for owner in previous_readiness_owners.values()):
            raise SystemdReconcileError("previous systemd reconcile field readinessOwners is malformed")

    previous_link_keys = _state_link_keys("links", previous) if previous else set()
    previous_quadlet_link_keys = _state_link_keys("quadletLinks", previous) if previous else set()
    current_links = {target: str(source) for target, source in sorted(links.items())}
    current_quadlet_links = {target: str(source) for target, source in sorted(quadlet_links.items())}
    stale_links = (previous_link_keys | _discover_systemd_links(systemd_runtime_dir)) - set(links)
    stale_quadlet_links = (previous_quadlet_link_keys | _discover_quadlet_links(quadlet_runtime_dir)) - set(
        quadlet_links
    )

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
    lifecycle_changed = (
        owned != previous_owned
        or start != previous_start
        or stop != previous_stop
        or readiness != previous_readiness
        or readiness_owners != previous_readiness_owners
    )
    fingerprint_changed = fingerprints != previous_fingerprints
    if previous and not topology_changed and not lifecycle_changed and not fingerprint_changed:
        return {"stopped": [], "changed": [], "started": [], "noop": True}

    retired_units = previous_owned - owned
    units_to_stop = retired_units | (previous_start - start) | stop
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

    # Session instances are transient systemd-run units. Restarting their
    # owning target relaunches them with the OLD Podman argv baked into
    # ExecStart, so a changed session must be stopped and explicitly
    # relaunched from the new descriptor.
    changed_sessions = {
        unit for unit in changed_units if _SESSION_TARGET.fullmatch(unit) and unit in previous_links_raw
    }
    units_to_stop.update(changed_sessions)

    def unit_state(unit: str) -> str | None:
        try:
            result = _run_systemctl(systemctl, "is-active", unit, check=False)
        except SystemdReconcileError:
            return None
        state = result.stdout.strip()
        return state if state in _UNIT_QUERY_STATES.get(result.returncode, ()) else None

    def is_active(unit: str, *, activating_is_active: bool = False) -> bool | None:
        state = unit_state(unit)
        if activating_is_active and state == "activating":
            return True
        return None if state is None or state in _TRANSITIONAL_UNIT_STATES else state in _UNIT_QUERY_STATES[0]

    planned_activations = ((changed_units & owned) - readiness - changed_sessions) | (
        (start - previous_start) - readiness
    )
    # Unchanged probes still gate an activated owner, but unrelated applies
    # must not be rejected by a workload they did not change or activate.
    readiness_to_run = {
        unit
        for unit in readiness
        if unit not in previous_readiness
        or fingerprints.get(unit) != previous_fingerprints.get(unit)
        or readiness_owners[unit] != previous_readiness_owners.get(unit)
        or readiness_owners[unit] in planned_activations
    }
    all_units = units_to_stop | (changed_units & owned) | (start - previous_start) | readiness_to_run
    all_units.update(readiness_owners[gate] for gate in readiness_to_run)
    state_snapshot = {unit: unit_state(unit) for unit in sorted(all_units)}
    unstable_units = [
        unit for unit, state in state_snapshot.items() if state is None or state in _TRANSITIONAL_UNIT_STATES
    ]
    if unstable_units:
        raise SystemdReconcileError(f"unable to snapshot stable systemd state: {', '.join(unstable_units)}")
    active_snapshot = {unit: state in _UNIT_QUERY_STATES[0] for unit, state in state_snapshot.items()}
    observed_readiness = dict(state_snapshot)
    for unit in sorted((set(readiness_owners) | set(readiness_owners.values())) - set(observed_readiness)):
        observed_readiness[unit] = unit_state(unit)
    # An interrupted or partially recorded apply can leave a target active with
    # no installed link. Stop it before installing the changed descriptor.
    active_unlinked_sessions = {
        unit
        for unit in changed_units
        if _SESSION_TARGET.fullmatch(unit)
        and unit not in previous_links_raw
        and unit in current_links
        and active_snapshot.get(unit) is True
    }
    changed_sessions.update(active_unlinked_sessions)
    units_to_stop.update(active_unlinked_sessions)

    roots = _projection_roots(projection_root)
    systemd_targets = set(links) | stale_links
    quadlet_targets = set(quadlet_links) | stale_quadlet_links
    live_systemd: dict[str, pathlib.Path | None] = {}
    live_quadlet: dict[str, pathlib.Path | None] = {}
    for target_rel in sorted(systemd_targets):
        target_path, _ = _safe_target(systemd_runtime_dir, target_rel)
        live_systemd[target_rel] = (
            None if target_path.is_symlink() and not target_path.exists() else _read_owned_link(target_path, roots)
        )
    for target_rel in sorted(quadlet_targets):
        target_path, _ = _safe_quadlet_target(quadlet_runtime_dir, target_rel)
        live_quadlet[target_rel] = (
            None if target_path.is_symlink() and not target_path.exists() else _read_owned_link(target_path, roots)
        )

    def rollback_links() -> None:
        _update_links(systemd_runtime_dir, live_systemd, roots)
        _update_links(quadlet_runtime_dir, live_quadlet, roots, quadlet=True)
        if topology_changed:
            _run_systemctl(systemctl, "daemon-reload")

    disrupted_sessions: set[str] = set()

    def rollback_active_state(*, links_restored: bool) -> list[str]:
        errors: list[str] = []
        for unit, was_active in active_snapshot.items():
            if unit in disrupted_sessions:
                # Starting this target cannot recreate its lost transient instances.
                continue
            now_active = is_active(unit, activating_is_active=was_active is False and unit in activated_units)
            if was_active is None or now_active is None:
                errors.append(f"unable to verify rollback active state for {unit}")
                continue
            if now_active == was_active:
                continue
            if was_active and not links_restored:
                errors.append(f"cannot safely start {unit} without restored links")
                continue
            try:
                _run_systemctl(systemctl, "start" if was_active else "stop", unit, timeout_seconds=activation_timeout)
            except SystemdReconcileError as error:
                errors.append(str(error))
        return errors

    activated_units: set[str] = set()
    attempted_readiness: set[str] = set()
    state_commit_attempted = False

    def discover_dependency_activations(*, include_readiness: bool) -> None:
        for owner in sorted(set(readiness_owners.values()) - activated_units):
            before = observed_readiness[owner]
            if before not in {"inactive", "failed", "unknown"}:
                continue
            now = unit_state(owner)
            if now is None:
                state_snapshot[owner] = before
                active_snapshot[owner] = False
                raise SystemdReconcileError(f"unable to inspect dependency activation: {owner}")
            if now not in _UNIT_QUERY_STATES[0] | {"activating"}:
                continue
            activated_units.add(owner)
            state_snapshot[owner] = before
            active_snapshot[owner] = False
            if not include_readiness:
                continue
            for gate, gate_owner in readiness_owners.items():
                if gate_owner != owner:
                    continue
                prior = observed_readiness[gate]
                if prior is None or prior in _TRANSITIONAL_UNIT_STATES:
                    raise SystemdReconcileError(f"unable to snapshot dependency readiness: {gate}")
                state_snapshot[gate] = prior
                active_snapshot[gate] = prior in _UNIT_QUERY_STATES[0]
                readiness_to_run.add(gate)

    for unit, expected in state_snapshot.items():
        if unit_state(unit) != expected:
            raise SystemdReconcileError(f"systemd state changed before mutation: {unit}; retry after it settles")
    try:
        for unit in sorted(units_to_stop):
            if _SESSION_TARGET.fullmatch(unit) and unit not in previous_links_raw and unit not in current_links:
                # A disabled or retired session has no installed target to stop.
                continue
            if _SESSION_TARGET.fullmatch(unit) and (unit in previous_owned or unit in active_unlinked_sessions):
                # Stopping a target terminates its transient instances. Record
                # this before the call so a partial failure is still reported.
                disrupted_sessions.add(unit)
            result = _run_systemctl(systemctl, "stop", unit, check=False)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()
                # A unit that is unknown to the manager or cannot be started
                # because it is not loaded/masked is already stopped; tolerate
                # those documented statuses and keep stopping the rest.
                if not any(marker in detail.lower() for marker in _ALREADY_STOPPED_STATUSES):
                    raise SystemdReconcileError(f"systemctl stop {unit} failed: {detail}")
        for unit in sorted(retired_units):
            _run_systemctl(systemctl, "reset-failed", unit, check=False)

        _update_links(systemd_runtime_dir, links, roots)
        _update_links(quadlet_runtime_dir, quadlet_links, roots, quadlet=True)
        _update_links(systemd_runtime_dir, dict.fromkeys(sorted(stale_links)), roots)
        _update_links(quadlet_runtime_dir, dict.fromkeys(sorted(stale_quadlet_links)), roots, quadlet=True)

        if topology_changed:
            _run_systemctl(systemctl, "daemon-reload")

        restarted: set[str] = set()
        for unit in sorted((changed_units & owned) - readiness):
            if unit in changed_sessions:
                # A stopped transient must not be restarted with stale args.
                continue
            activated_units.add(unit)
            if unit in start:
                _run_systemctl(systemctl, "restart", unit, timeout_seconds=activation_timeout)
                restarted.add(unit)
            else:
                _run_systemctl(systemctl, "try-restart", unit, timeout_seconds=activation_timeout)

        units_to_start = (start - previous_start) - restarted - readiness
        for unit in sorted(units_to_start):
            activated_units.add(unit)
            _run_systemctl(systemctl, "start", unit, timeout_seconds=activation_timeout)

        discover_dependency_activations(include_readiness=True)
        if readiness_to_run:
            attempted_readiness.update(readiness_to_run)
            _run_systemctl(systemctl, "restart", *sorted(readiness_to_run), timeout_seconds=activation_timeout)
            restarted.update(readiness_to_run)

        state = {
            "schemaVersion": 1,
            "activationTimeoutSeconds": manifest.get("activationTimeoutSeconds", _SYSTEMCTL_TIMEOUT_SECONDS),
            "links": current_links,
            "linkHashes": current_hashes,
            "quadletLinks": current_quadlet_links,
            "quadletHashes": current_quadlet_hashes,
            "ownedUnits": sorted(owned),
            "startUnits": sorted(start),
            "readinessUnits": sorted(readiness),
            "readinessOwners": readiness_owners,
            "stopUnits": sorted(stop),
            "fingerprints": fingerprints,
        }
        state_commit_attempted = True
        _atomic_json(state_path, state)
        return {
            "stopped": sorted(units_to_stop),
            "changed": sorted(changed_units),
            "started": sorted(units_to_start | restarted),
            "noop": False,
        }
    except Exception as exc:
        rollback_errors: list[str] = []
        if activated_units:
            # A failed consumer start can still have activated its dependencies.
            try:
                discover_dependency_activations(include_readiness=False)
            except SystemdReconcileError as discovery_exc:
                rollback_errors.append(str(discovery_exc))
        links_restored = False
        try:
            rollback_links()
        except Exception as rollback_exc:  # noqa: BLE001
            rollback_errors.append(str(rollback_exc))
        else:
            links_restored = True
            # Restoring links cannot replace a still-active candidate process,
            # including when activation or the state commit reports failure.
            for unit in sorted(activated_units):
                if active_snapshot.get(unit) is True and unit not in disrupted_sessions:
                    try:
                        _run_systemctl(systemctl, "restart", unit, timeout_seconds=activation_timeout)
                    except SystemdReconcileError as restart_exc:
                        rollback_errors.append(str(restart_exc))
        rollback_errors.extend(rollback_active_state(links_restored=links_restored))
        if not rollback_errors:
            for unit in sorted(attempted_readiness):
                if active_snapshot.get(unit) is not False or state_snapshot.get(unit) == "failed":
                    continue
                try:
                    state = unit_state(unit)
                    if state is None:
                        raise SystemdReconcileError(f"unable to verify readiness rollback state for {unit}")
                    if state == "failed":
                        _run_systemctl(systemctl, "reset-failed", unit)
                except SystemdReconcileError as reset_exc:
                    rollback_errors.append(str(reset_exc))
        if state_commit_attempted:
            try:
                try:
                    published = state_path.read_bytes()
                except FileNotFoundError:
                    published = None
                if published != previous_bytes:
                    if previous_bytes is None:
                        state_path.unlink(missing_ok=True)
                        _fsync_directory(state_path.parent)
                    else:
                        _atomic_bytes(state_path, previous_bytes)
            except Exception as state_exc:  # noqa: BLE001
                rollback_errors.append(f"unable to restore reconcile state: {state_exc}")
        rollback_error = "; ".join(rollback_errors)
        prior_failures = sorted(unit for unit in attempted_readiness if state_snapshot.get(unit) == "failed")
        failure_detail = str(exc)
        if prior_failures:
            failure_detail += f"; readiness units already failed before apply: {', '.join(prior_failures)}"
        if disrupted_sessions:
            details = ", ".join(sorted(disrupted_sessions))
            rollback_detail = f"; native rollback failed: {rollback_error}" if rollback_error else ""
            raise SystemdReconcileError(
                f"systemd reconcile failed: {failure_detail}{rollback_detail}; transient instances may have been "
                f"terminated under {details} and cannot be recreated by target restart; manual recovery required"
            ) from exc
        if rollback_error:
            raise SystemdReconcileError(
                f"systemd reconcile failed: {failure_detail}; rollback failed: {rollback_error}; manual recovery required"
            ) from exc
        if isinstance(exc, SystemdReconcileError) and not prior_failures:
            raise
        raise SystemdReconcileError(failure_detail) from exc


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
