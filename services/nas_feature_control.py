#!/usr/bin/env python3
"""Persistent and on-demand runtime feature control for the NAS appliance.

Nix installs packages and declares safe unit defaults. This controller owns the
small mutable layer which decides whether optional features are off, started on
first authorized access, or kept resident. The HTTP authorization gate is bound
to a root-owned Unix socket and is called by Caddy only after Authentik forward
authentication.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import pathlib
import re
import socket
import secrets
import socketserver
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any

from nas_common import (
    ADMIN_GROUP,
    CAPABILITY_GROUPS,
    DISABLED_GROUP,
    CommandResult,
    capability_allowed,
    parse_systemd_show,
    run_command,
    effective_feature_modes,
    split_groups,
)

from nas_operation_lock import (
    COORDINATION_TOKEN_ENV,
    OperationBusyError,
    acquire_operation,
    validate_coordination_token,
)

from nas_feature_model import (
    VALID_MODES,
    FeatureError,
    FeatureFileMissingError,
    WakeCache,
    default_state,
    entry_allowed_modes,
    feature_chain,
    feature_graph,
    migrate_mode,
    normalize_catalog as normalize_catalog_contract,
)

CATALOG_PATH = pathlib.Path(os.environ.get("NAS_FEATURE_CATALOG", "/etc/nas-control/features.json"))
_SCHEMA_DEFAULT = pathlib.Path(__file__).resolve().parents[1] / "schemas" / "feature-catalog.schema.json"
SCHEMA_PATH = pathlib.Path(os.environ.get("NAS_FEATURE_SCHEMA", str(_SCHEMA_DEFAULT)))
STATE_PATH = pathlib.Path(os.environ.get("NAS_FEATURE_STATE", "/var/lib/nas-control/settings.json"))
JOURNAL_PATH = pathlib.Path(os.environ.get("NAS_FEATURE_JOURNAL", "/var/lib/nas-control/transaction.json"))
LAST_GOOD_PATH = pathlib.Path(os.environ.get("NAS_FEATURE_LAST_GOOD", "/var/lib/nas-control/settings.last-good.json"))
RUNTIME_PATH = pathlib.Path(os.environ.get("NAS_FEATURE_RUNTIME", "/run/nas-control/on-demand.json"))
LOCK_PATH = pathlib.Path(os.environ.get("NAS_FEATURE_LOCK", "/var/lib/nas-control/feature-control.lock"))
SOCKET_PATH = pathlib.Path(os.environ.get("NAS_ON_DEMAND_SOCKET", "/run/nas-on-demand/gate.sock"))
REAPER_INTERVAL = max(5, int(os.environ.get("NAS_ON_DEMAND_REAPER_INTERVAL", "30")))
TOUCH_INTERVAL = max(1, int(os.environ.get("NAS_ON_DEMAND_TOUCH_INTERVAL", "10")))
WAKE_CACHE_SECONDS = max(0.0, float(os.environ.get("NAS_ON_DEMAND_WAKE_CACHE_SECONDS", "2")))
LOCK_TIMEOUT_SECONDS = max(0.1, float(os.environ.get("NAS_FEATURE_LOCK_TIMEOUT_SECONDS", "10")))
MAX_GATE_WORKERS = max(1, int(os.environ.get("NAS_ON_DEMAND_MAX_WORKERS", "8")))
COMMAND_TIMEOUT_SECONDS = max(1.0, float(os.environ.get("NAS_FEATURE_COMMAND_TIMEOUT_SECONDS", "120")))
COMMAND_MAX_OUTPUT_BYTES = max(4096, int(os.environ.get("NAS_FEATURE_COMMAND_MAX_OUTPUT_BYTES", str(256 * 1024))))
AI_API_KEY_FILE = pathlib.Path(os.environ.get("NAS_AI_API_KEY_FILE", "/run/nas-secrets/ai/llama-swap.env"))

AI_ALLOW_GROUP, AI_DENY_GROUP = CAPABILITY_GROUPS["ai"]
GATE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
GATE_SCOPES = frozenset({"", "admin", "authenticated", "network", "ai-api", *CAPABILITY_GROUPS})


@contextlib.contextmanager
def mutation_operation(action: str):
    """Join the appliance-wide runtime coordinator unless a parent already owns it."""

    token = os.environ.get(COORDINATION_TOKEN_ENV)
    if token:
        try:
            validate_coordination_token(token, ("runtime",))
        except OperationBusyError as exc:
            raise FeatureError(str(exc)) from exc
        yield
        return
    try:
        with acquire_operation(action, ("runtime",), blocking=False):
            yield
    except OperationBusyError as exc:
        raise FeatureError(str(exc)) from exc


OPERATION_LOCK = threading.RLock()
FEATURE_LOCKS_GUARD = threading.Lock()
FEATURE_LOCKS: dict[str, threading.RLock] = {}


WAKE_CACHE = WakeCache()


def run(cmd: list[str]) -> CommandResult:
    """Compatibility wrapper retained for unit-test injection."""

    return run_command(
        cmd,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=COMMAND_MAX_OUTPUT_BYTES,
    )


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FeatureFileMissingError(f"Required feature file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FeatureError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FeatureError(f"Expected a JSON object in {path}")
    return value


def read_optional_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        return read_json(path)
    except (FeatureFileMissingError, OSError):
        return {}


def atomic_write_json(path: pathlib.Path, value: dict[str, Any], mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        replaced = True
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if not replaced:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def acquire_lock(*, blocking: bool = False, timeout: float | None = None) -> Any:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = LOCK_PATH.open("a+")
    if not blocking:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except BlockingIOError as exc:
            handle.close()
            raise FeatureError("Another feature operation is already running") from exc

    deadline = time.monotonic() + (LOCK_TIMEOUT_SECONDS if timeout is None else max(0.0, timeout))
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except BlockingIOError as exc:
            if time.monotonic() >= deadline:
                handle.close()
                raise FeatureError("Timed out waiting for another feature operation") from exc
            time.sleep(0.05)


def feature_operation_lock(feature_id: str) -> threading.RLock:
    with FEATURE_LOCKS_GUARD:
        return FEATURE_LOCKS.setdefault(feature_id, threading.RLock())


def catalog_contract() -> tuple[set[str], set[str], set[str], set[str]]:
    """Load the committed JSON Schema as the authoritative field contract."""

    schema = read_json(SCHEMA_PATH)
    try:
        top_fields = set(schema["properties"])
        definitions = schema["$defs"]
        feature_fields = set(definitions["feature"]["properties"])
        probe_fields = set(definitions["availabilityProbe"]["properties"])
        memory_fields = set(definitions["memoryComponent"]["properties"])
    except (KeyError, TypeError) as exc:
        raise FeatureError(f"Malformed feature catalog schema in {SCHEMA_PATH}") from exc
    return top_fields, feature_fields, probe_fields, memory_fields


def normalize_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    return normalize_catalog_contract(catalog, catalog_contract())


def load_catalog() -> dict[str, Any]:
    return normalize_catalog(read_json(CATALOG_PATH))


def state_checksum(state: dict[str, Any]) -> str:
    payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_last_good(state: dict[str, Any]) -> None:
    atomic_write_json(
        LAST_GOOD_PATH,
        {
            "schemaVersion": 1,
            "stateSchemaVersion": state.get("schemaVersion"),
            "checksum": state_checksum(state),
            "state": state,
        },
    )


def remove_transaction_journal() -> None:
    try:
        JOURNAL_PATH.unlink()
    except FileNotFoundError:
        return
    directory_fd = os.open(JOURNAL_PATH.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def quarantine_transaction_journal(reason: str) -> pathlib.Path:
    """Move one malformed journal out of the reaper path for operator inspection."""

    suffix = f".corrupt-{int(time.time())}-{secrets.token_hex(4)}"
    destination = JOURNAL_PATH.with_name(JOURNAL_PATH.name + suffix)
    try:
        os.replace(JOURNAL_PATH, destination)
        directory_fd = os.open(JOURNAL_PATH.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise FeatureError(
            f"Malformed feature transaction journal could not be quarantined: {JOURNAL_PATH}: {exc}"
        ) from exc
    print(
        f"nas-on-demand: quarantined malformed transaction journal at {destination}: {reason}",
        file=sys.stderr,
    )
    return destination


def recover_pending_transaction(catalog: dict[str, Any]) -> None:
    if not JOURNAL_PATH.exists():
        return
    try:
        journal = read_json(JOURNAL_PATH)
    except (FeatureError, OSError) as exc:
        quarantined = quarantine_transaction_journal(str(exc))
        raise FeatureError(f"Malformed feature transaction journal quarantined at {quarantined}") from exc
    previous = journal.get("previous")
    runtime_before = journal.get("runtimeBefore")
    if (
        journal.get("schemaVersion") != 1
        or not isinstance(previous, dict)
        or not isinstance(runtime_before, dict)
        or not all(isinstance(unit, str) and isinstance(active, bool) for unit, active in runtime_before.items())
    ):
        quarantined = quarantine_transaction_journal("journal contract validation failed")
        raise FeatureError(f"Malformed feature transaction journal quarantined at {quarantined}")
    restore_runtime_snapshot(catalog, runtime_before)
    atomic_write_json(STATE_PATH, previous)
    write_last_good(previous)
    remove_transaction_journal()


def load_state(catalog: dict[str, Any]) -> dict[str, Any]:
    recover_pending_transaction(catalog)
    defaults = default_state(catalog)
    try:
        state = read_json(STATE_PATH)
    except FeatureFileMissingError:
        atomic_write_json(STATE_PATH, defaults)
        write_last_good(defaults)
        return defaults
    if state.get("schemaVersion") not in {1, 2} or not isinstance(state.get("features"), dict):
        raise FeatureError(f"Unsupported or malformed state in {STATE_PATH}")
    merged = default_state(catalog)
    for feature_id, requested in state["features"].items():
        entry = catalog["features"].get(feature_id)
        if isinstance(entry, dict):
            mode = migrate_mode(requested, entry)
            if mode is None:
                raise FeatureError(f"Feature {feature_id} has malformed or unsupported state value {requested!r}")
            merged["features"][feature_id] = mode
    merged["updatedAt"] = int(state.get("updatedAt") or merged["updatedAt"])
    if merged != state:
        atomic_write_json(STATE_PATH, merged)
    if not LAST_GOOD_PATH.exists():
        write_last_good(merged)
    return merged


def effective_modes(catalog: dict[str, Any], state: dict[str, Any]) -> dict[str, str]:
    """Compatibility wrapper around the shared feature-policy evaluator."""

    return effective_feature_modes(catalog, state)


def persistent_features(catalog: dict[str, Any], state: dict[str, Any]) -> set[str]:
    features = catalog["features"]
    modes = effective_modes(catalog, state)
    persistent: set[str] = set()
    for feature_id, mode in modes.items():
        if mode == "always":
            persistent.update(feature_chain(feature_id, features))
    return {feature_id for feature_id in persistent if modes.get(feature_id) != "off"}


def systemd_unit_snapshot(units: list[str]) -> dict[str, dict[str, str]]:
    """Fetch active state and memory for many units with one systemctl call."""

    unique_units = list(dict.fromkeys(units))
    if not unique_units:
        return {}
    result = run(
        [
            "systemctl",
            "show",
            "--property=Id,ActiveState,SubState,Result,MemoryCurrent",
            *unique_units,
        ]
    )
    return parse_systemd_show(result.stdout)


def ordered_feature_units(catalog: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return code-owned start and stop order for every catalog unit."""

    features: dict[str, Any] = catalog["features"]
    depths, _ = feature_graph(features)
    feature_order = sorted(features, key=lambda item: (depths[item], item))
    start_order: list[str] = []
    stop_order: list[str] = []
    for feature_id in feature_order:
        start_order.extend(str(unit) for unit in features[feature_id].get("startUnits", []))
    for feature_id in reversed(feature_order):
        entry = features[feature_id]
        stop_order.extend(str(unit) for unit in (entry.get("stopUnits") or reversed(entry.get("startUnits", []))))
    return list(dict.fromkeys(start_order)), list(dict.fromkeys(stop_order))


def capture_runtime_snapshot(catalog: dict[str, Any]) -> dict[str, bool]:
    start_order, stop_order = ordered_feature_units(catalog)
    units = list(dict.fromkeys([*start_order, *stop_order]))
    snapshot = systemd_unit_snapshot(units)
    return {unit: snapshot_unit_active(snapshot, unit) for unit in units}


def restore_runtime_snapshot(catalog: dict[str, Any], expected: dict[str, bool]) -> dict[str, Any]:
    """Restore and verify the exact observed active/inactive unit set."""

    start_order, stop_order = ordered_feature_units(catalog)
    current = capture_runtime_snapshot(catalog)
    operations: list[dict[str, Any]] = []
    to_stop = [unit for unit in stop_order if current.get(unit, False) and not expected.get(unit, False)]
    if to_stop:
        operations.extend(stop_units(to_stop))
    current = capture_runtime_snapshot(catalog)
    to_start = [unit for unit in start_order if expected.get(unit, False) and not current.get(unit, False)]
    if to_start:
        operations.extend(start_units(to_start))
    final = capture_runtime_snapshot(catalog)
    mismatches = {
        unit: {"expectedActive": active, "observedActive": final.get(unit, False)}
        for unit, active in expected.items()
        if final.get(unit, False) != active
    }
    failures = [item for item in operations if not item["ok"]]
    if failures or mismatches:
        detail = "; ".join(
            [f"{item['action']} {item['unit']}: {item['error']}" for item in failures]
            + [
                f"{unit}: expected active={value['expectedActive']} observed={value['observedActive']}"
                for unit, value in mismatches.items()
            ]
        )
        raise FeatureError(f"Unable to restore exact feature runtime state: {detail}")
    return {"ok": True, "operations": operations, "observed": final}


def snapshot_unit_active(snapshot: dict[str, dict[str, str]], unit: str) -> bool:
    return snapshot.get(unit, {}).get("ActiveState") == "active"


def snapshot_unit_memory(snapshot: dict[str, dict[str, str]], unit: str) -> int | None:
    value = snapshot.get(unit, {}).get("MemoryCurrent", "")
    if not value.isdigit():
        return None
    parsed = int(value)
    return None if parsed >= 2**63 else parsed


def unit_active(unit: str) -> bool:
    return run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def units_running(units: list[str]) -> bool:
    return bool(units) and all(unit_active(unit) for unit in units)


def unit_memory_bytes(unit: str) -> int | None:
    result = run(["systemctl", "show", unit, "--property=MemoryCurrent", "--value"])
    value = result.stdout.strip()
    if result.returncode != 0 or not value.isdigit():
        return None
    parsed = int(value)
    if parsed >= 2**63:
        return None
    return parsed


def start_units(units: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for unit in units:
        result = run(["systemctl", "start", unit])
        results.append(
            {
                "unit": unit,
                "action": "start",
                "ok": result.returncode == 0,
                "error": (result.stderr or result.stdout).strip(),
            }
        )
        if result.returncode != 0:
            break
    return results


def stop_units(units: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for unit in units:
        result = run(["systemctl", "stop", unit])
        results.append(
            {
                "unit": unit,
                "action": "stop",
                "ok": result.returncode == 0,
                "error": (result.stderr or result.stdout).strip(),
            }
        )
    return results


def apply(
    catalog: dict[str, Any],
    state: dict[str, Any],
    *,
    strict: bool,
    preserve_on_demand: bool = False,
) -> dict[str, Any]:
    features: dict[str, Any] = catalog["features"]
    modes = effective_modes(catalog, state)
    persistent = persistent_features(catalog, state)
    depths, _ = feature_graph(features)
    ordered = sorted(features, key=lambda item: (depths[item], item))
    all_units = [
        str(unit)
        for entry in features.values()
        for unit in set(entry.get("startUnits", [])) | set(entry.get("stopUnits", []))
    ]
    snapshot = systemd_unit_snapshot(all_units)
    active = {unit for unit in all_units if snapshot_unit_active(snapshot, unit)}
    operations: list[dict[str, Any]] = []

    for feature_id in reversed(ordered):
        entry = features[feature_id]
        if not bool(entry.get("available", False)):
            continue
        mode = modes[feature_id]
        if feature_id in persistent or (preserve_on_demand and mode == "on-demand"):
            continue
        units = list(entry.get("stopUnits") or reversed(entry.get("startUnits", [])))
        selected = [unit for unit in units if unit in active]
        if selected:
            results = stop_units(selected)
            operations.extend(results)
            active.difference_update(item["unit"] for item in results if item["ok"])

    for feature_id in ordered:
        if feature_id not in persistent:
            continue
        units = list(features[feature_id].get("startUnits", []))
        inactive = [unit for unit in units if unit not in active]
        if inactive:
            results = start_units(inactive)
            operations.extend(results)
            active.update(item["unit"] for item in results if item["ok"])

    failures = [item for item in operations if not item["ok"]]
    if strict and failures:
        first = failures[0]
        raise FeatureError(f"Unable to {first['action']} {first['unit']}: {first['error']}")
    return {
        "ok": not failures,
        "effective": {feature_id: mode != "off" for feature_id, mode in modes.items()},
        "effectiveModes": modes,
        "persistent": sorted(persistent),
        "operations": operations,
        "failures": failures,
    }


def arm_running_on_demand(catalog: dict[str, Any], state: dict[str, Any]) -> None:
    modes = effective_modes(catalog, state)
    candidates = [feature_id for feature_id, mode in modes.items() if mode == "on-demand"]
    units = [str(unit) for feature_id in candidates for unit in catalog["features"][feature_id].get("startUnits", [])]
    snapshot = systemd_unit_snapshot(units)
    running = [
        feature_id
        for feature_id in candidates
        if any(snapshot_unit_active(snapshot, unit) for unit in catalog["features"][feature_id].get("startUnits", []))
    ]
    if running:
        touch_runtime(running)


def commit_state_transactionally(
    catalog: dict[str, Any],
    state: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    previous = json.loads(json.dumps(state))
    runtime_before = capture_runtime_snapshot(catalog)
    journal = {
        "schemaVersion": 1,
        "phase": "prepared",
        "createdAt": int(time.time()),
        "previousChecksum": state_checksum(previous),
        "candidateChecksum": state_checksum(candidate),
        "runtimeBefore": runtime_before,
        "previous": previous,
        "candidate": candidate,
    }
    atomic_write_json(JOURNAL_PATH, journal, mode=0o600)
    runtime_changed = False
    try:
        runtime_changed = True
        result = apply(catalog, candidate, strict=True, preserve_on_demand=True)
        journal["phase"] = "runtime-applied"
        atomic_write_json(JOURNAL_PATH, journal, mode=0o600)
        atomic_write_json(STATE_PATH, candidate)
        journal["phase"] = "state-persisted"
        atomic_write_json(JOURNAL_PATH, journal, mode=0o600)
        write_last_good(candidate)
        remove_transaction_journal()
        WAKE_CACHE.clear()
        arm_running_on_demand(catalog, candidate)
        state.clear()
        state.update(candidate)
        return result
    except (FeatureError, OSError) as exc:
        rollback_errors: list[str] = []
        if runtime_changed:
            try:
                restore_runtime_snapshot(catalog, runtime_before)
            except Exception as rollback_exc:  # noqa: BLE001
                rollback_errors.append(str(rollback_exc))
        try:
            atomic_write_json(STATE_PATH, previous)
            write_last_good(previous)
        except OSError as persistence_exc:
            rollback_errors.append(str(persistence_exc))
        if rollback_errors:
            journal["phase"] = "manual-recovery-required"
            journal["rollbackErrors"] = rollback_errors
            try:
                atomic_write_json(JOURNAL_PATH, journal, mode=0o600)
            except OSError:
                pass
            raise FeatureError(
                f"Feature state update failed and rollback was incomplete; inspect {JOURNAL_PATH}"
            ) from exc
        remove_transaction_journal()
        state.clear()
        state.update(previous)
        if isinstance(exc, FeatureError):
            raise
        raise FeatureError("Unable to persist feature state; runtime changes were rolled back") from exc


def set_mode(catalog: dict[str, Any], state: dict[str, Any], feature_id: str, mode: str) -> dict[str, Any]:
    entry = catalog["features"].get(feature_id)
    if not isinstance(entry, dict):
        raise FeatureError(f"Unknown feature: {feature_id}")
    if mode not in entry_allowed_modes(entry):
        raise FeatureError(f"Feature {feature_id} does not support mode {mode}")
    if mode != "off" and not bool(entry.get("available", False)):
        raise FeatureError(f"Feature {feature_id} is not installed in this NixOS generation")
    candidate = json.loads(json.dumps(state))
    candidate["features"][feature_id] = mode
    candidate["updatedAt"] = int(time.time())
    result = commit_state_transactionally(catalog, state, candidate)
    return {"feature": feature_id, "requestedMode": mode, **result}


def set_modes(catalog: dict[str, Any], state: dict[str, Any], requested: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(requested, dict):
        raise FeatureError("Feature mode document must be a JSON object")
    candidate = json.loads(json.dumps(state))
    normalized: dict[str, str] = {}
    for feature_id, raw_mode in requested.items():
        if not isinstance(feature_id, str) or not isinstance(raw_mode, str):
            raise FeatureError("Feature mode document must map feature identifiers to strings")
        entry = catalog["features"].get(feature_id)
        if not isinstance(entry, dict):
            raise FeatureError(f"Unknown feature: {feature_id}")
        if raw_mode not in entry_allowed_modes(entry):
            raise FeatureError(f"Feature {feature_id} does not support mode {raw_mode}")
        if raw_mode != "off" and not bool(entry.get("available", False)):
            raise FeatureError(f"Feature {feature_id} is not installed in this NixOS generation")
        normalized[feature_id] = raw_mode
    for feature_id, mode in normalized.items():
        candidate["features"][feature_id] = mode
    candidate["updatedAt"] = int(time.time())
    result = commit_state_transactionally(catalog, state, candidate)
    return {"requestedModes": normalized, **result}


def read_mode_document(source: str) -> dict[str, Any]:
    try:
        text = sys.stdin.read() if source == "-" else pathlib.Path(source).read_text(encoding="utf-8")
        value = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise FeatureError(f"Unable to read feature mode document from {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise FeatureError("Feature mode document must be a JSON object")
    return value


def set_feature(catalog: dict[str, Any], state: dict[str, Any], feature_id: str, enabled: bool) -> dict[str, Any]:
    """Compatibility wrapper used by old callers and migration tests."""
    return set_mode(catalog, state, feature_id, "always" if enabled else "off")


def runtime_state() -> dict[str, Any]:
    value = read_optional_json(RUNTIME_PATH)
    if value.get("schemaVersion") != 1 or not isinstance(value.get("features"), dict):
        return {"schemaVersion": 1, "features": {}}
    return value


def save_runtime(value: dict[str, Any]) -> None:
    atomic_write_json(RUNTIME_PATH, value, mode=0o640)


def touch_runtime(feature_ids: list[str], *, started: dict[str, int] | None = None) -> dict[str, Any]:
    value = runtime_state()
    now = int(time.time())
    changed = False
    for feature_id in feature_ids:
        record = value["features"].setdefault(feature_id, {})
        prior_access = int(record.get("lastAccess", 0))
        if started and feature_id in started:
            record["lastAccess"] = now
            record["lastReadyAt"] = now
            record["lastStartDurationMs"] = started[feature_id]
            record["startCount"] = int(record.get("startCount", 0)) + 1
            changed = True
        elif now - prior_access >= TOUCH_INTERVAL:
            record["lastAccess"] = now
            changed = True
    if changed:
        save_runtime(value)
    return value


def wait_ready(entry: dict[str, Any]) -> None:
    health_urls = [str(url) for url in entry.get("healthUrls", [])]
    health_url = entry.get("healthUrl")
    if isinstance(health_url, str):
        health_urls.append(health_url)
    health_ports: list[int] = []
    health_port = entry.get("healthPort")
    if isinstance(health_port, int):
        health_ports.append(health_port)
    if not health_urls and not health_ports:
        return
    timeout = max(1, int(entry.get("startupTimeoutSeconds", 60)))
    deadline = time.monotonic() + timeout
    last_error = "not ready"
    while time.monotonic() < deadline:
        try:
            for url in health_urls:
                request = urllib.request.Request(url, method="GET", headers={"User-Agent": "nas-on-demand/1"})
                with urllib.request.urlopen(request, timeout=2) as response:
                    if not 200 <= response.status < 400:
                        raise FeatureError(f"{url} returned HTTP {response.status}")
            for port in health_ports:
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    pass
            return
        except urllib.error.HTTPError as exc:
            if 400 <= exc.code < 500 and exc.code not in {408, 425, 429}:
                raise FeatureError(
                    f"{entry.get('label', 'Feature')} readiness endpoint is misconfigured: "
                    f"{exc.url} returned HTTP {exc.code}"
                ) from exc
            last_error = str(exc)
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
        except FeatureError:
            raise
        time.sleep(0.5)
    raise FeatureError(f"{entry.get('label', 'Feature')} did not become ready within {timeout}s: {last_error}")


def wake_feature(catalog: dict[str, Any], state: dict[str, Any], feature_id: str) -> dict[str, Any]:
    features = catalog["features"]
    if feature_id not in features:
        raise FeatureError(f"Unknown feature: {feature_id}")
    modes = effective_modes(catalog, state)
    if modes.get(feature_id) == "off":
        raise FeatureError(f"Feature {feature_id} is disabled")
    chain = feature_chain(feature_id, features)
    cached_at = WAKE_CACHE.get(feature_id, 0.0)
    if WAKE_CACHE_SECONDS > 0 and time.monotonic() - cached_at < WAKE_CACHE_SECONDS:
        chain_units = [str(unit) for current in chain for unit in features[current].get("startUnits", [])]
        snapshot = systemd_unit_snapshot(chain_units)
        target_healthy, _ = observed_health(features[feature_id])
        if all(snapshot_unit_active(snapshot, unit) for unit in chain_units) and target_healthy:
            touch_runtime(chain)
            return {
                "ok": True,
                "feature": feature_id,
                "chain": chain,
                "operations": [],
                "startDurationsMs": {},
                "cached": True,
            }
        WAKE_CACHE.pop(feature_id)

    chain_units = [str(unit) for current in chain for unit in features[current].get("startUnits", [])]
    snapshot = systemd_unit_snapshot(chain_units)
    active = {unit for unit in chain_units if snapshot_unit_active(snapshot, unit)}
    operations: list[dict[str, Any]] = []
    started_units: list[str] = []
    durations: dict[str, int] = {}
    try:
        for current in chain:
            if modes.get(current) == "off":
                raise FeatureError(f"Feature dependency {current} is disabled")
            entry = features[current]
            units = list(entry.get("startUnits", []))
            inactive = [unit for unit in units if unit not in active]
            started_at = time.monotonic()
            if inactive:
                results = start_units(inactive)
                operations.extend(results)
                successful = [item["unit"] for item in results if item["ok"]]
                started_units.extend(successful)
                active.update(successful)
                failure = next((item for item in results if not item["ok"]), None)
                if failure:
                    raise FeatureError(f"Unable to start {failure['unit']}: {failure['error']}")
            if units:
                wait_ready(entry)
            if inactive:
                durations[current] = int((time.monotonic() - started_at) * 1000)
        touch_runtime(chain, started=durations)
        WAKE_CACHE.record(feature_id, time.monotonic())
        return {
            "ok": True,
            "feature": feature_id,
            "chain": chain,
            "operations": operations,
            "startDurationsMs": durations,
            "cached": False,
        }
    except FeatureError:
        if started_units:
            stop_units(list(reversed(started_units)))
        raise


def established_on_ports(ports: list[int]) -> bool:
    if not ports:
        return False
    wanted = set(ports)
    for path in (pathlib.Path("/proc/net/tcp"), pathlib.Path("/proc/net/tcp6")):
        try:
            lines = path.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "01":
                continue
            local = fields[1]
            try:
                port = int(local.rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            if port in wanted:
                return True
    return False


def reap(catalog: dict[str, Any], state: dict[str, Any], *, now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    features = catalog["features"]
    modes = effective_modes(catalog, state)
    persistent = persistent_features(catalog, state)
    runtime = runtime_state()
    depths, descendants_by_id = feature_graph(features)
    ordered = sorted(features, key=lambda item: (depths[item], item), reverse=True)
    all_units = [
        str(unit)
        for entry in features.values()
        for unit in set(entry.get("startUnits", [])) | set(entry.get("stopUnits", []))
    ]
    snapshot = systemd_unit_snapshot(all_units)
    active = {unit for unit in all_units if snapshot_unit_active(snapshot, unit)}
    operations: list[dict[str, Any]] = []
    stopped: list[str] = []

    def active_descendant(feature_id: str) -> bool:
        return any(
            unit in active for child in descendants_by_id[feature_id] for unit in features[child].get("startUnits", [])
        )

    for feature_id in ordered:
        with feature_operation_lock(feature_id):
            entry = features[feature_id]
            if modes.get(feature_id) != "on-demand" or feature_id in persistent:
                continue
            units = list(entry.get("startUnits", []))
            if not units or not any(unit in active for unit in units):
                continue
            record = runtime.get("features", {}).get(feature_id, {})
            last_access = int(record.get("lastAccess", 0))
            idle_seconds = int(entry.get("idleSeconds", 0))
            if last_access <= 0 or now - last_access < idle_seconds:
                continue
            if active_descendant(feature_id) or established_on_ports(
                [int(port) for port in entry.get("activePorts", [])]
            ):
                continue
            stop_order = list(entry.get("stopUnits") or reversed(units))
            selected = [unit for unit in stop_order if unit in active]
            results = stop_units(selected)
            operations.extend(results)
            active.difference_update(item["unit"] for item in results if item["ok"])
            if all(item["ok"] for item in results):
                WAKE_CACHE.pop(feature_id)
                stopped.append(feature_id)
    return {"ok": all(item["ok"] for item in operations), "stopped": stopped, "operations": operations}


def meminfo() -> dict[str, int]:
    result: dict[str, int] = {}
    try:
        lines = pathlib.Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"nas-feature-control: unable to read /proc/meminfo: {exc}", file=sys.stderr)
        return result
    for line in lines:
        key, _, raw = line.partition(":")
        fields = raw.strip().split()
        if fields and fields[0].isdigit():
            result[key] = int(fields[0]) * 1024
    return result


def memory_report(
    catalog: dict[str, Any],
    state: dict[str, Any],
    *,
    unit_snapshot: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    modes = effective_modes(catalog, state)
    persistent = persistent_features(catalog, state)
    rows: list[dict[str, Any]] = []
    totals = {
        "resident": {"min": 0, "typical": 0, "max": 0},
        "activeNow": {"min": 0, "typical": 0, "max": 0},
        "allConfigured": {"min": 0, "typical": 0, "max": 0},
    }
    for component in catalog.get("memoryComponents", []):
        if not isinstance(component, dict):
            continue
        feature = component.get("feature")
        installed = bool(component.get("installed", True))
        mode = modes.get(str(feature), "always") if feature is not None else "always"
        configured = installed and mode != "off"
        resident = installed and (feature is None or str(feature) in persistent)
        units = [str(unit) for unit in component.get("units", [])]
        current_values = [
            snapshot_unit_memory(unit_snapshot, unit) if unit_snapshot is not None else unit_memory_bytes(unit)
            for unit in units
        ]
        current = sum(value for value in current_values if value is not None)
        active_units = (
            any(snapshot_unit_active(unit_snapshot, unit) for unit in units)
            if unit_snapshot is not None
            else any(unit_active(unit) for unit in units)
        )
        active_observed = configured and bool(units) and active_units
        healthy_observed = (
            configured and (not units or all(snapshot_unit_active(unit_snapshot, unit) for unit in units))
            if unit_snapshot is not None
            else configured and (not units or all(unit_active(unit) for unit in units))
        )
        estimate = {
            "min": int(component.get("minMiB", 0)),
            "typical": int(component.get("typicalMiB", 0)),
            "max": int(component.get("maxMiB", 0)),
        }
        row = {
            "id": component.get("id"),
            "label": component.get("label"),
            "feature": feature,
            "installed": installed,
            "mode": mode if feature is not None else "core",
            "configured": configured,
            "resident": resident,
            "residentExpected": resident,
            "active": active_observed,
            "activeObserved": active_observed,
            "healthyObserved": healthy_observed,
            "included": resident,
            "estimateMiB": estimate,
            "currentBytes": current if any(value is not None for value in current_values) else None,
            "units": units,
            "notes": component.get("notes", ""),
        }
        rows.append(row)
        for bucket, include in (("resident", resident), ("activeNow", active_observed), ("allConfigured", configured)):
            if include:
                for key in ("min", "typical", "max"):
                    totals[bucket][key] += estimate[key]
    info = meminfo()
    return {
        "components": rows,
        "estimateMiB": totals["resident"],
        "residentEstimateMiB": totals["resident"],
        "activeEstimateMiB": totals["activeNow"],
        "configuredMaximumMiB": totals["allConfigured"],
        "onDemandSavingsMiB": {
            key: totals["allConfigured"][key] - totals["resident"][key] for key in ("min", "typical", "max")
        },
        "system": {
            "totalBytes": info.get("MemTotal"),
            "availableBytes": info.get("MemAvailable"),
            "cachedBytes": (info.get("Cached", 0) + info.get("SReclaimable", 0)) or None,
        },
        "zfsArcExcluded": True,
        "note": "Resident estimates include core and always-on features. On-demand services are added only while active. ZFS ARC is excluded.",
    }


def observed_health(entry: dict[str, Any], *, timeout: float = 0.5) -> tuple[bool, str | None]:
    urls = [str(url) for url in entry.get("healthUrls", [])]
    if isinstance(entry.get("healthUrl"), str):
        urls.append(str(entry["healthUrl"]))
    ports = [int(entry["healthPort"])] if isinstance(entry.get("healthPort"), int) else []
    if not urls and not ports:
        return True, None
    try:
        for url in urls:
            request = urllib.request.Request(url, method="GET", headers={"User-Agent": "nas-status/2"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if not 200 <= response.status < 400:
                    return False, f"health endpoint returned HTTP {response.status}"
        for port in ports:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout):
                pass
    except (OSError, TimeoutError, urllib.error.URLError):
        return False, "readiness probe failed"
    return True, None


def runtime_availability(entry: dict[str, Any]) -> tuple[bool, str | None]:
    """Evaluate a structured, non-shell runtime availability probe."""

    probe = entry.get("availabilityProbe")
    if not isinstance(probe, dict):
        return True, None
    probe_type = probe["type"]
    try:
        if probe_type == "path":
            available = pathlib.Path(probe["path"]).exists()
        elif probe_type == "device-any":
            available = any(pathlib.Path(path).exists() for path in probe["paths"])
        elif probe_type == "executable":
            path = pathlib.Path(probe["path"])
            available = path.is_file() and os.access(path, os.X_OK)
        elif probe_type == "systemd-unit":
            result = run(["systemctl", "show", "--property=LoadState", "--value", probe["unit"]])
            available = result.returncode == 0 and result.stdout.strip() == "loaded"
        elif probe_type == "tcp":
            with socket.create_connection((probe.get("host", "127.0.0.1"), int(probe["port"])), timeout=1):
                available = True
        elif probe_type == "http":
            request = urllib.request.Request(probe["url"], method="GET", headers={"User-Agent": "nas-status/1"})
            with urllib.request.urlopen(request, timeout=2) as response:
                available = 200 <= response.status < 500
        else:
            available = False
    except (OSError, TimeoutError, urllib.error.URLError):
        available = False
    return available, None if available else str(probe.get("description") or f"{probe_type} probe failed")


def status(catalog: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    features: dict[str, Any] = catalog["features"]
    requested: dict[str, str] = state["features"]
    modes = effective_modes(catalog, state)
    persistent = persistent_features(catalog, state)
    runtime = runtime_state().get("features", {})
    now = int(time.time())
    _, descendants_by_id = feature_graph(features)
    all_units = [str(unit) for entry in features.values() for unit in entry.get("startUnits", [])]
    all_units.extend(
        str(unit)
        for component in catalog.get("memoryComponents", [])
        if isinstance(component, dict)
        for unit in component.get("units", [])
    )
    unit_snapshot = systemd_unit_snapshot(all_units)
    output: list[dict[str, Any]] = []
    for feature_id, entry in features.items():
        units = list(entry.get("startUnits", []))
        record = runtime.get(feature_id, {}) if isinstance(runtime, dict) else {}
        last_access = int(record.get("lastAccess", 0)) if isinstance(record, dict) else 0
        idle_seconds = int(entry.get("idleSeconds", 0))
        unit_states = [unit_snapshot.get(unit, {}).get("ActiveState", "unknown") for unit in units]
        active_count = sum(state_name == "active" for state_name in unit_states)
        running = active_count > 0 if units else modes[feature_id] != "off"
        runtime_available, availability_reason = runtime_availability(entry)
        health_ok, health_reason = observed_health(entry) if active_count == len(units) else (False, None)
        if any(state_name == "failed" for state_name in unit_states):
            health_state = "failed"
        elif not units:
            health_state = "healthy" if modes[feature_id] != "off" and runtime_available else "inactive"
        elif active_count == 0:
            health_state = "inactive"
        elif active_count < len(units):
            health_state = "starting" if any(state_name == "activating" for state_name in unit_states) else "degraded"
        elif not health_ok:
            health_state = "degraded"
        else:
            health_state = "healthy"
        remaining = None
        if modes[feature_id] == "on-demand" and running and last_access > 0:
            remaining = max(0, idle_seconds - (now - last_access))
        held_by = [
            child for child in descendants_by_id[feature_id] if child in persistent and modes.get(child) != "off"
        ]
        output.append(
            {
                "id": feature_id,
                "label": entry.get("label", feature_id),
                "description": entry.get("description", ""),
                "available": bool(entry.get("available", False)),
                "runtimeAvailable": runtime_available,
                "availabilityReason": availability_reason,
                "allowedModes": entry_allowed_modes(entry),
                "requestedMode": str(requested.get(feature_id, "off")),
                "requested": str(requested.get(feature_id, "off")) != "off",
                "effectiveMode": modes[feature_id],
                "effective": modes[feature_id] != "off",
                "resident": feature_id in persistent,
                "running": running,
                "healthState": health_state,
                "healthy": health_state == "healthy",
                "healthReason": health_reason,
                "parent": entry.get("parent"),
                "idleSeconds": idle_seconds or None,
                "idleRemainingSeconds": remaining,
                "lastAccess": last_access or None,
                "lastStartDurationMs": record.get("lastStartDurationMs") if isinstance(record, dict) else None,
                "startupEstimateSeconds": entry.get("startupEstimateSeconds"),
                "heldBy": held_by,
                "restartRequired": bool(entry.get("restartRequired", False)),
                "units": [
                    {
                        "unit": unit,
                        "active": snapshot_unit_active(unit_snapshot, unit),
                        "memoryBytes": snapshot_unit_memory(unit_snapshot, unit),
                    }
                    for unit in units
                ],
            }
        )
    return {
        "schemaVersion": 2,
        "updatedAt": state.get("updatedAt"),
        "features": output,
        "memory": memory_report(catalog, state, unit_snapshot=unit_snapshot),
    }


def ai_api_key() -> str:
    try:
        text = AI_API_KEY_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise FeatureError("AI API authentication is unavailable") from exc
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "LLAMA_SWAP_API_KEY":
            secret = value.strip()
            if 8 <= len(secret) <= 4096:
                return secret
    secret = text.strip()
    if 8 <= len(secret) <= 4096 and "\n" not in secret:
        return secret
    raise FeatureError("AI API authentication is unavailable")


def ai_api_authorized(headers: Any) -> bool:
    authorization = str(headers.get("Authorization", "")).strip()
    supplied = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if not supplied:
        supplied = str(headers.get("X-API-Key", "")).strip()
    if not supplied:
        return False
    return hmac.compare_digest(supplied, ai_api_key())


def authorize(entry: dict[str, Any], headers: Any, scope: str = "") -> bool:
    if scope == "ai-api":
        return ai_api_authorized(headers)
    access = str(entry.get("access", "admin"))
    groups = split_groups(headers.get("Remote-Groups", ""))
    username = headers.get("Remote-User", "").strip()
    if access == "network":
        return True
    if DISABLED_GROUP in groups or not username:
        return False
    if access == "authenticated":
        return True
    capability = scope if scope in CAPABILITY_GROUPS else access if access in CAPABILITY_GROUPS else None
    if capability is not None:
        return capability_allowed(groups, capability)
    return ADMIN_GROUP in groups


def authorize_service_scope(scope: str, headers: Any) -> bool:
    try:
        _, service_id, endpoint_id = scope.split(":", 2)
    except ValueError:
        return False
    key = f"{service_id}:{endpoint_id}"
    try:
        effective_path = pathlib.Path(os.environ.get("NAS_EFFECTIVE_REGISTRY", "/run/nas-control/effective-endpoints.json"))
        effective = json.loads(effective_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        try:
            import nas_managed_service as msvc

            effective = msvc.effective_registry()
        except Exception:
            return False
    endpoint = effective.get("endpoints", {}).get(key)
    if not isinstance(endpoint, dict):
        return False
    auth = endpoint.get("auth") or {}
    mode = auth.get("mode", endpoint.get("access", "admin"))
    if mode == "public":
        return True
    groups = split_groups(headers.get("Remote-Groups", ""))
    username = headers.get("Remote-User", "").strip()
    if DISABLED_GROUP in groups or not username:
        return False
    if ADMIN_GROUP in groups:
        return True
    allow = auth.get("allow", "any")
    allowed_groups = auth.get("groups") or []
    allowed_users = auth.get("users") or []
    if allow == "any":
        return bool(username)
    if allow == "groups":
        return any(g in groups for g in allowed_groups)
    if allow == "users":
        return username in allowed_users
    if allow == "all":
        return (not allowed_groups or any(g in groups for g in allowed_groups)) and (not allowed_users or username in allowed_users)
    if allowed_groups:
        return any(g in groups for g in allowed_groups)
    if allowed_users:
        return username in allowed_users
    return False


class BoundedThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._request_slots = threading.BoundedSemaphore(MAX_GATE_WORKERS)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(timeout=0.1):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n"
                    b"Content-Length: 13\r\nConnection: close\r\n\r\nGate is busy\n"
                )
            finally:
                self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class GateHandler(BaseHTTPRequestHandler):
    server_version = "NASOnDemand/2"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Never emit raw request lines/query strings; authorization decisions
        # are reported through bounded operation diagnostics instead.
        return

    def respond(self, status: HTTPStatus, body: str = "") -> None:
        payload = body.encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if status == HTTPStatus.SERVICE_UNAVAILABLE:
            self.send_header("Retry-After", "5")
        self.end_headers()
        if self.command != "HEAD" and payload:
            self.wfile.write(payload)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/authorize":
            self.respond(HTTPStatus.NOT_FOUND, "Not found\n")
            return
        try:
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, max_num_fields=4)
        except ValueError:
            self.respond(HTTPStatus.BAD_REQUEST, "Invalid authorization query\n")
            return
        if set(query) - {"feature", "scope"} or any(len(values) != 1 for values in query.values()):
            self.respond(HTTPStatus.BAD_REQUEST, "Invalid authorization query\n")
            return
        feature_id = query.get("feature", [""])[0]
        scope = query.get("scope", [""])[0]
        if scope.startswith("service:"):
            if authorize_service_scope(scope, self.headers):
                self.respond(HTTPStatus.NO_CONTENT)
            else:
                self.respond(HTTPStatus.FORBIDDEN, "Not authorized for this service endpoint\n")
            return
        if (feature_id and GATE_ID_RE.fullmatch(feature_id) is None) or scope not in GATE_SCOPES:
            self.respond(HTTPStatus.BAD_REQUEST, "Invalid authorization query\n")
            return
        if not feature_id and scope in CAPABILITY_GROUPS:
            if authorize({}, self.headers, scope):
                self.respond(HTTPStatus.NO_CONTENT)
            else:
                self.respond(HTTPStatus.FORBIDDEN, "Not authorized for this capability\n")
            return
        reference = secrets.token_hex(6)
        try:
            catalog = load_catalog()
            entry = catalog["features"].get(feature_id)
            if not isinstance(entry, dict):
                raise FeatureError("Unknown on-demand feature")
            if not authorize(entry, self.headers, scope):
                self.respond(HTTPStatus.FORBIDDEN, "Not authorized for this feature\n")
                return
            with (
                mutation_operation(f"feature-wake:{feature_id}"),
                feature_operation_lock(feature_id),
                acquire_lock(blocking=True),
            ):
                state = load_state(catalog)
                wake_feature(catalog, state, feature_id)
            self.respond(HTTPStatus.NO_CONTENT)
        except FeatureError as exc:
            print(f"nas-on-demand: request {reference} unavailable: {exc}", file=sys.stderr)
            self.respond(HTTPStatus.SERVICE_UNAVAILABLE, f"Feature unavailable (reference {reference})\n")
        except Exception as exc:  # noqa: BLE001
            print(f"nas-on-demand: request {reference} failed: {exc}", file=sys.stderr)
            self.respond(HTTPStatus.INTERNAL_SERVER_ERROR, f"Feature gate failed (reference {reference})\n")


def reaper_loop(stop_event: threading.Event) -> None:
    while not stop_event.wait(REAPER_INTERVAL):
        try:
            catalog = load_catalog()
            with mutation_operation("feature-reap"), acquire_lock(blocking=True):
                state = load_state(catalog)
                reap(catalog, state)
        except Exception as exc:  # noqa: BLE001
            print(f"nas-on-demand: idle reaper failed: {exc}", file=sys.stderr)


def serve() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        if SOCKET_PATH.exists() or SOCKET_PATH.is_socket():
            SOCKET_PATH.unlink()
    except OSError as exc:
        raise FeatureError(f"Unable to remove stale socket {SOCKET_PATH}: {exc}") from exc
    server = BoundedThreadingUnixHTTPServer(str(SOCKET_PATH), GateHandler)
    os.chmod(SOCKET_PATH, 0o660)
    stop_event = threading.Event()
    thread = threading.Thread(target=reaper_loop, args=(stop_event,), name="nas-idle-reaper", daemon=True)
    thread.start()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stop_event.set()
        server.server_close()
        try:
            SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Report feature, on-demand, and memory state")
    sub.add_parser("apply", help="Apply persistent feature state to systemd")
    set_parser = sub.add_parser("set", help="Set one feature to off, on-demand, or always")
    set_parser.add_argument("feature")
    set_parser.add_argument("mode", choices=sorted(VALID_MODES))
    set_many_parser = sub.add_parser("set-many", help="Apply one complete feature-mode document transactionally")
    set_many_parser.add_argument("source", help="JSON object file or - for standard input")
    wake_parser = sub.add_parser("wake", help="Start an enabled feature and its dependencies")
    wake_parser.add_argument("feature")
    sub.add_parser("reap", help="Stop expired on-demand features")
    sub.add_parser("reset", help="Reset persistent feature state to Nix-provided defaults")
    sub.add_parser("serve", help="Serve the authenticated on-demand Caddy gate")
    args = parser.parse_args()

    if args.command == "serve":
        try:
            serve()
            return 0
        except (FeatureError, OSError, ValueError) as exc:
            print(f"nas-feature-control: {exc}", file=sys.stderr)
            return 1

    try:
        mutation_commands = {"apply", "set", "set-many", "wake", "reap", "reset"}
        operation = (
            mutation_operation(f"feature-{args.command}")
            if args.command in mutation_commands
            else contextlib.nullcontext()
        )
        with operation, OPERATION_LOCK, acquire_lock():
            catalog = load_catalog()
            state = load_state(catalog)
            if args.command == "status":
                result = status(catalog, state)
            elif args.command == "apply":
                result = apply(catalog, state, strict=False, preserve_on_demand=False)
                result["status"] = status(catalog, state)
            elif args.command == "set":
                result = set_mode(catalog, state, args.feature, args.mode)
                result["status"] = status(catalog, state)
            elif args.command == "set-many":
                result = set_modes(catalog, state, read_mode_document(args.source))
                result["status"] = status(catalog, state)
            elif args.command == "wake":
                result = wake_feature(catalog, state, args.feature)
                result["status"] = status(catalog, state)
            elif args.command == "reap":
                result = reap(catalog, state)
                result["status"] = status(catalog, state)
            else:
                candidate = default_state(catalog)
                result = commit_state_transactionally(catalog, state, candidate)
                result["status"] = status(catalog, state)
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.command in {"apply", "reap"} and not result.get("ok", False):
            return 1
        return 0
    except (FeatureError, OSError, ValueError) as exc:
        print(f"nas-feature-control: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
