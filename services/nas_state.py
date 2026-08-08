#!/usr/bin/env python3
"""Strict export, drift detection, validation, and recovery for appliance state."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import pathlib
import pwd
import grp
import re
import secrets
import signal
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping

from nas_operation_journal import atomic_write_json
from nas_operation_lock import (
    COORDINATION_TOKEN_ENV,
    OperationBusyError,
    acquire_operation,
    validate_coordination_token,
)

SCHEMA_VERSION = 2
REGISTRY_VERSION = 1
BUNDLE_MANIFEST = "manifest.json"
PAYLOAD_ROOT = "payload"
DEFAULT_ROLLBACK_ROOT = pathlib.Path(os.environ.get("NAS_STATE_ROLLBACK_ROOT", "/var/lib/nas-state"))
DEFAULT_RUNTIME_ROOT = pathlib.Path(os.environ.get("NAS_STATE_RUNTIME_ROOT", "/run/nas-state"))
MAX_ARCHIVE_MEMBERS = int(os.environ.get("NAS_STATE_MAX_ARCHIVE_MEMBERS", "100000"))
MAX_ARCHIVE_BYTES = int(os.environ.get("NAS_STATE_MAX_ARCHIVE_BYTES", str(20 * 1024 * 1024 * 1024)))
MAX_ARCHIVE_MEMBER_NAME_BYTES = 4096
MAX_ARCHIVE_COMPONENT_BYTES = 255
ROLLBACK_RETAIN_COUNT = max(1, int(os.environ.get("NAS_STATE_ROLLBACK_RETAIN_COUNT", "5")))
ROLLBACK_RETAIN_SECONDS = max(0, int(os.environ.get("NAS_STATE_ROLLBACK_RETAIN_SECONDS", str(30 * 24 * 60 * 60))))
COMMAND_OUTPUT_LIMIT = max(4096, int(os.environ.get("NAS_STATE_COMMAND_OUTPUT_BYTES", str(256 * 1024))))
_SCHEMA_DEFAULT = pathlib.Path(__file__).resolve().parents[1] / "schemas" / "state-bundle.schema.json"
SCHEMA_PATH = pathlib.Path(os.environ.get("NAS_STATE_SCHEMA", str(_SCHEMA_DEFAULT)))
PRODUCER_VERSION = os.environ.get("NAS_VERSION", "unknown")
SOURCE_REVISION = os.environ.get("NAS_SOURCE_REVISION", "unknown")
SIGNING_KEY_PATH = pathlib.Path(os.environ.get("NAS_STATE_SIGNING_KEY", "/run/nas-secrets/state/bundle-signing-key"))
RESTORE_JOURNAL = pathlib.Path(os.environ.get("NAS_STATE_RESTORE_JOURNAL", "/var/lib/nas-state/restore-operation.json"))
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class StateError(RuntimeError):
    """Expected appliance-state operation failure."""


@dataclass(frozen=True)
class Authority:
    name: str
    source: str
    kind: str = "path"
    sensitive: bool = False
    optional: bool = False
    restoreStrategy: str = "path-policy"
    owner: str | None = None
    group: str | None = None
    rootMode: str | None = None


@dataclass(frozen=True)
class Entry:
    name: str
    source: str
    kind: str
    sensitive: bool
    status: str
    payload: str | None
    digest: str | None
    comparisonDigest: str | None = None


@dataclass(frozen=True)
class PathPolicy:
    uid: int
    gid: int
    root_mode: int
    sensitive: bool


def default_authorities() -> tuple[Authority, ...]:
    """Fallback registry for direct development use; Nix installs a profile-aware registry."""

    return (
        Authority("feature-control", os.environ.get("NAS_FEATURE_STATE_ROOT", "/var/lib/nas-control")),
        Authority("first-run", os.environ.get("NAS_SETUP_STATE_ROOT", "/var/lib/nas-setup"), optional=True),
        Authority("firewall", os.environ.get("NAS_FIREWALL_STATE_ROOT", "/var/lib/nas-firewall"), optional=True),
        Authority(
            "networkmanager",
            os.environ.get("NAS_NETWORKMANAGER_STATE_ROOT", "/etc/NetworkManager/system-connections"),
            sensitive=True,
            optional=True,
        ),
        Authority(
            "copyparty",
            os.environ.get("NAS_COPYPARTY_STATE_ROOT", "/var/lib/copyparty"),
            sensitive=True,
        ),
        Authority(
            "syncthing",
            os.environ.get("NAS_SYNCTHING_STATE_ROOT", "/var/lib/syncthing/.config/syncthing"),
            sensitive=True,
            optional=True,
        ),
        Authority(
            "identity-sync",
            os.environ.get("NAS_IDENTITY_SYNC_STATE_ROOT", "/var/lib/nas-identity-sync"),
            sensitive=True,
        ),
        Authority(
            "scheduler",
            os.environ.get("NAS_SCHEDULER_STATE_ROOT", "/var/lib/cockpit-scheduler"),
            optional=True,
        ),
        Authority(
            "caddy",
            os.environ.get("NAS_CADDY_STATE_ROOT", "/var/lib/caddy"),
            sensitive=True,
        ),
        Authority(
            "authentik-media",
            os.environ.get("NAS_AUTHENTIK_STATE_ROOT", "/var/lib/authentik/data"),
            sensitive=True,
        ),
        Authority(
            "keepass",
            os.environ.get("NAS_KEEPASS_DATABASE", "/var/lib/nas-secrets/NAS.kdbx"),
            sensitive=True,
        ),
        Authority("authentik-database", "postgresql://authentik", kind="database", sensitive=True),
        Authority(
            "managed-services",
            os.environ.get("NAS_MANAGED_SERVICES_STATE_ROOT", "/var/lib/nas-control/services.json"),
        ),
        Authority(
            "managed-apps",
            os.environ.get("NAS_MANAGED_APPS_STATE_ROOT", "/var/lib/nas-control/apps"),
            optional=True,
        ),
    )


def _load_registry_value() -> Any:
    registry_file = os.environ.get("NAS_STATE_REGISTRY_FILE")
    raw = os.environ.get("NAS_STATE_REGISTRY_JSON")
    if registry_file:
        try:
            return json.loads(pathlib.Path(registry_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StateError(f"Invalid state registry file: {registry_file}") from exc
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StateError("NAS_STATE_REGISTRY_JSON is invalid JSON") from exc


def authorities() -> tuple[Authority, ...]:
    value = _load_registry_value()
    if value is None:
        if os.environ.get("NAS_STATE_REGISTRY_REQUIRED") == "1":
            raise StateError("Generated state registry is required in installed/production execution")
        result = list(default_authorities())
    else:
        if not isinstance(value, list):
            raise StateError("State registry must be an array")
        result = []
        for item in value:
            if not isinstance(item, dict):
                raise StateError("Every state authority must be an object")
            expected_fields = {
                "name",
                "source",
                "kind",
                "sensitive",
                "optional",
                "restoreStrategy",
                "owner",
                "group",
                "rootMode",
            }
            if set(item) != expected_fields:
                raise StateError(
                    "State authority fields must exactly match "
                    "name/source/kind/sensitive/optional/restoreStrategy/owner/group/rootMode"
                )
            if not isinstance(item["name"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", item["name"]):
                raise StateError("State authority name is invalid")
            if not isinstance(item["source"], str) or not item["source"]:
                raise StateError(f"State authority {item['name']} has an invalid source")
            if item["kind"] not in {"path", "database"}:
                raise StateError(f"State authority {item['name']} has an invalid kind")
            if not isinstance(item["sensitive"], bool) or not isinstance(item["optional"], bool):
                raise StateError(f"State authority {item['name']} has invalid boolean fields")
            if item["restoreStrategy"] not in {"path-policy", "database-native"}:
                raise StateError(f"State authority {item['name']} has an invalid restore strategy")
            if item["kind"] == "path":
                if item["restoreStrategy"] != "path-policy":
                    raise StateError(f"Path authority {item['name']} must use path-policy restore")
                if not isinstance(item["owner"], str) or not item["owner"]:
                    raise StateError(f"Path authority {item['name']} requires an owner")
                if not isinstance(item["group"], str) or not item["group"]:
                    raise StateError(f"Path authority {item['name']} requires a group")
                if not isinstance(item["rootMode"], str) or not re.fullmatch(r"0[0-7]{3}", item["rootMode"]):
                    raise StateError(f"Path authority {item['name']} has an invalid root mode")
            elif (
                item["restoreStrategy"] != "database-native"
                or item["owner"] is not None
                or item["group"] is not None
                or item["rootMode"] is not None
            ):
                raise StateError(f"Database authority {item['name']} has invalid restore policy fields")
            result.append(Authority(**item))
    names = [item.name for item in result]
    if len(names) != len(set(names)):
        raise StateError("State authority names must be unique")
    return tuple(result)


def registry_digest(registry: Iterable[Authority]) -> str:
    payload = json.dumps([asdict(item) for item in registry], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def require_root() -> None:
    if os.geteuid() != 0 and os.environ.get("NAS_STATE_ALLOW_UNPRIVILEGED") != "1":
        raise StateError("nas-state export and restore require root")


def runtime_root() -> pathlib.Path:
    """Return a private staging root; production defaults to tmpfs-backed /run."""

    configured = os.environ.get("NAS_STATE_RUNTIME_ROOT")
    if configured:
        root = pathlib.Path(configured)
    elif os.environ.get("NAS_STATE_ALLOW_UNPRIVILEGED") == "1" and os.geteuid() != 0:
        root = pathlib.Path(tempfile.gettempdir()) / f"nas-state-{os.geteuid()}"
    else:
        root = DEFAULT_RUNTIME_ROOT
    mode = lstat_type(root)
    if mode and (stat.S_ISLNK(mode) or not stat.S_ISDIR(mode)):
        raise StateError(f"State runtime root is not a trusted directory: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    if os.geteuid() == 0:
        os.chown(root, 0, 0)
    return root


def state_temporary_directory(prefix: str) -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix=prefix, dir=runtime_root())


def lstat_type(path: pathlib.Path) -> int:
    try:
        return path.lstat().st_mode
    except FileNotFoundError:
        return 0


def ensure_safe_tree(path: pathlib.Path) -> None:
    mode = lstat_type(path)
    if mode == 0:
        return
    if stat.S_ISLNK(mode):
        raise StateError(f"State authority may not be a symlink: {path}")
    if stat.S_ISREG(mode):
        return
    if not stat.S_ISDIR(mode):
        raise StateError(f"State authority is not a regular file or directory: {path}")
    for child in path.rglob("*"):
        child_mode = child.lstat().st_mode
        if stat.S_ISLNK(child_mode):
            raise StateError(f"State authority contains a symlink: {child}")
        if not (stat.S_ISDIR(child_mode) or stat.S_ISREG(child_mode)):
            raise StateError(f"State authority contains an unsupported object: {child}")


def hash_path(path: pathlib.Path) -> str:
    ensure_safe_tree(path)
    digest = hashlib.sha256()
    mode = path.lstat().st_mode
    root = path.parent if stat.S_ISREG(mode) else path
    paths = [path] if stat.S_ISREG(mode) else [path, *sorted(path.rglob("*"))]
    for item in paths:
        metadata = item.lstat()
        relative = item.relative_to(root).as_posix()
        kind = "d" if stat.S_ISDIR(metadata.st_mode) else "f"
        digest.update(f"{kind}\0{relative}\0{stat.S_IMODE(metadata.st_mode) & 0o777:o}\0".encode())
        if stat.S_ISREG(metadata.st_mode):
            with item.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
    return digest.hexdigest()


def apply_safe_mode(source: pathlib.Path, target: pathlib.Path) -> None:
    mode = stat.S_IMODE(source.lstat().st_mode) & 0o777
    os.chmod(target, mode, follow_symlinks=False)


def copy_authority(source: pathlib.Path, target: pathlib.Path) -> None:
    ensure_safe_tree(source)
    mode = source.lstat().st_mode
    if stat.S_ISDIR(mode):
        shutil.copytree(source, target, copy_function=shutil.copy2, symlinks=False)
        apply_safe_mode(source, target)
        for child in source.rglob("*"):
            apply_safe_mode(child, target / child.relative_to(source))
    elif stat.S_ISREG(mode):
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)
        apply_safe_mode(source, target)
    else:
        raise StateError(f"Unsupported authority source: {source}")


def bounded(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= COMMAND_OUTPUT_LIMIT:
        return value
    return encoded[:COMMAND_OUTPUT_LIMIT].decode("utf-8", errors="replace") + "\n[output truncated]"


def _drain_bounded(stream: Any, *, limit: int, result: list[str]) -> None:
    kept = bytearray()
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if len(kept) < limit:
            kept.extend(chunk[: limit - len(kept)])
    text = bytes(kept).decode("utf-8", errors="replace")
    if total > limit:
        text += "\n[output truncated]"
    result.append(text)


def run_process(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout_result: list[str] = []
    stderr_result: list[str] = []
    stdout_thread = threading.Thread(
        target=_drain_bounded,
        args=(process.stdout,),
        kwargs={"limit": COMMAND_OUTPUT_LIMIT, "result": stdout_result},
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_drain_bounded,
        args=(process.stderr,),
        kwargs={"limit": COMMAND_OUTPUT_LIMIT, "result": stderr_result},
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        # The helpers used here can be wrappers (for example runuser) that spawn
        # database children. Kill the complete session before rollback starts.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        raise StateError(f"Command timed out: {command[0]}") from exc
    finally:
        stdout_thread.join()
        stderr_thread.join()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout_result[0] if stdout_result else "",
        stderr_result[0] if stderr_result else "",
    )


def database_command(variable: str, default: list[str], placeholder: str, value: str) -> list[str]:
    raw = os.environ.get(variable)
    if raw is None:
        command = default
    else:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StateError(f"{variable} must be a JSON command array") from exc
        if not isinstance(parsed, list) or not parsed or not all(isinstance(item, str) and item for item in parsed):
            raise StateError(f"{variable} must be a nonempty JSON command array")
        command = parsed
    return [value if item == placeholder else item for item in command]


def dump_database(target: pathlib.Path) -> None:
    command = database_command(
        "NAS_STATE_PG_DUMP_COMMAND",
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "pg_dump",
            "--format=custom",
            "--no-owner",
            "--file",
            "{output}",
            "authentik",
        ],
        "{output}",
        str(target),
    )
    result = run_process(command, timeout=1800)
    if result.returncode != 0:
        raise StateError("Authentik database export failed")


def restore_database(source: pathlib.Path) -> None:
    command = database_command(
        "NAS_STATE_PG_RESTORE_COMMAND",
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--dbname=authentik",
            "{input}",
        ],
        "{input}",
        str(source),
    )
    result = run_process(command, timeout=1800)
    if result.returncode != 0:
        raise StateError("Authentik database restore failed; rollback is required")


def database_comparison_digest() -> str:
    """Hash a normalized logical dump for meaningful database drift detection."""

    with state_temporary_directory("nas-state-db-compare.") as temporary:
        output = pathlib.Path(temporary) / "authentik.sql"
        command = database_command(
            "NAS_STATE_PG_COMPARE_COMMAND",
            [
                "runuser",
                "-u",
                "postgres",
                "--",
                "pg_dump",
                "--format=plain",
                "--no-owner",
                "--no-privileges",
                "--inserts",
                "--rows-per-insert=1",
                "--file",
                "{output}",
                "authentik",
            ],
            "{output}",
            str(output),
        )
        result = run_process(command, timeout=1800)
        if result.returncode != 0:
            raise StateError("Authentik database comparison export failed")
        digest = hashlib.sha256()
        try:
            with output.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if line.startswith(("-- Dumped from", "-- Dumped by", "-- Started on", "-- Completed on")):
                        continue
                    digest.update(line.rstrip().encode("utf-8"))
                    digest.update(b"\n")
        except OSError as exc:
            raise StateError("Authentik comparison dump is unavailable") from exc
        return digest.hexdigest()


def manifest_contract() -> tuple[set[str], set[str], set[str]]:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        top = set(schema["required"])
        entry_schema = schema["properties"]["entries"]["items"]
        entry = set(entry_schema["required"])
        statuses = set(entry_schema["properties"]["status"]["enum"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise StateError(f"Invalid committed state schema: {SCHEMA_PATH}") from exc
    return top, entry, statuses


def allow_unsigned_bundles() -> bool:
    return os.environ.get("NAS_STATE_ALLOW_UNSIGNED", "0") == "1"


def signing_key() -> bytes:
    key_path = pathlib.Path(os.environ.get("NAS_STATE_SIGNING_KEY", str(SIGNING_KEY_PATH)))
    try:
        raw = key_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        if allow_unsigned_bundles():
            return b""
        raise StateError(f"State bundle signing key is unavailable: {key_path}") from exc
    if not re.fullmatch(r"[0-9A-Fa-f]{64,256}", raw):
        raise StateError("State bundle signing key has an invalid format")
    return bytes.fromhex(raw)


def canonical_manifest_payload(manifest: Mapping[str, Any]) -> bytes:
    value = {key: manifest[key] for key in manifest if key != "signature"}
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: Mapping[str, Any]) -> str:
    key = signing_key()
    if not key and allow_unsigned_bundles():
        return "0" * 64
    return hmac.new(key, canonical_manifest_payload(manifest), hashlib.sha256).hexdigest()


def compatible_version(producer: str, current: str) -> bool:
    if current == "unknown":
        return True
    match_producer = re.match(r"^(\d+)\.(\d+)\.", producer)
    match_current = re.match(r"^(\d+)\.(\d+)\.", current)
    return bool(match_producer and match_current and match_producer.groups() == match_current.groups())


def write_manifest(
    staging: pathlib.Path,
    entries: list[Entry],
    include_sensitive: bool,
    registry: tuple[Authority, ...],
    *,
    snapshot_epoch: str,
    snapshot_started_at: int,
    snapshot_completed_at: int,
    quiesced_units: tuple[str, ...],
) -> dict[str, Any]:
    complete = all(item.status not in {"omitted-sensitive", "missing-required"} for item in entries)
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "registryVersion": REGISTRY_VERSION,
        "registryDigest": registry_digest(registry),
        "producerVersion": PRODUCER_VERSION,
        "sourceRevision": SOURCE_REVISION,
        "createdAt": int(time.time()),
        "hostName": socket.gethostname(),
        "snapshotEpoch": snapshot_epoch,
        "snapshotStartedAt": snapshot_started_at,
        "snapshotCompletedAt": snapshot_completed_at,
        "quiescedUnits": list(quiesced_units),
        "includeSensitive": include_sensitive,
        "complete": complete,
        "signatureAlgorithm": "hmac-sha256",
        "entries": [asdict(item) for item in entries],
    }
    manifest["signature"] = sign_manifest(manifest)
    staging.joinpath(BUNDLE_MANIFEST).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def deterministic_tar_add(archive: tarfile.TarFile, path: pathlib.Path, arcname: str) -> None:
    ensure_safe_tree(path)
    archive.add(path, arcname=arcname, recursive=True, filter=lambda info: _safe_tar_info(info))


def _safe_tar_info(info: tarfile.TarInfo) -> tarfile.TarInfo:
    if not (info.isdir() or info.isreg()):
        raise StateError(f"Unsupported object while creating state bundle: {info.name}")
    info.mode &= 0o777
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    return info


def export_quiesce_units() -> tuple[str, ...]:
    raw = os.environ.get("NAS_STATE_QUIESCE_UNITS_JSON")
    if raw:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StateError("NAS_STATE_QUIESCE_UNITS_JSON is invalid") from exc
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise StateError("NAS_STATE_QUIESCE_UNITS_JSON must be an array of unit names")
        return tuple(dict.fromkeys(value))
    return (
        "authentik.service",
        "authentik-worker.service",
        "nas-identity-sync.timer",
        "copyparty.service",
        "syncthing.service",
        "vaultwarden.service",
        "caddy.service",
    )


def should_quiesce_export() -> bool:
    return (
        os.geteuid() == 0
        and os.environ.get("NAS_STATE_ALLOW_UNPRIVILEGED") != "1"
        and os.environ.get("NAS_STATE_EXPORT_QUIESCE", "1") == "1"
    )


def validate_staging_limits(staging: pathlib.Path) -> tuple[int, int]:
    """Enforce the same expanded member/byte ceilings before export succeeds."""

    ensure_safe_tree(staging)
    members = [staging, *staging.rglob("*")]
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise StateError("State export exceeds the archive member limit")
    total = sum(item.lstat().st_size for item in members if stat.S_ISREG(item.lstat().st_mode))
    if total > MAX_ARCHIVE_BYTES:
        raise StateError("State export exceeds the extraction size limit")
    return len(members), total


def export_bundle(output: pathlib.Path, *, include_sensitive: bool, quiesce: bool | None = None) -> dict[str, Any]:
    require_root()
    registry = authorities()
    output.parent.mkdir(parents=True, exist_ok=True)
    snapshot_epoch = secrets.token_hex(16)
    snapshot_started_at = int(time.time())
    quiesced_units: tuple[str, ...] = ()
    unit_snapshot: dict[str, bool] = {}
    if should_quiesce_export() if quiesce is None else quiesce:
        quiesced_units = export_quiesce_units()
        unit_snapshot = capture_unit_state(quiesced_units)
        stop_active_units(unit_snapshot)
    try:
        with state_temporary_directory("nas-state-export.") as temporary:
            staging = pathlib.Path(temporary)
            payload_root = staging / PAYLOAD_ROOT
            payload_root.mkdir(mode=0o700)
            entries: list[Entry] = []
            for authority in registry:
                payload_name = f"{PAYLOAD_ROOT}/{authority.name}"
                payload_path = staging / payload_name
                if authority.sensitive and not include_sensitive:
                    entries.append(
                        Entry(authority.name, authority.source, authority.kind, True, "omitted-sensitive", None, None)
                    )
                    continue
                comparison_digest: str | None = None
                if authority.kind == "database":
                    payload_path.parent.mkdir(parents=True, exist_ok=True)
                    dump_database(payload_path)
                    os.chmod(payload_path, 0o600)
                    comparison_digest = database_comparison_digest()
                else:
                    source = pathlib.Path(authority.source)
                    if lstat_type(source) == 0:
                        status = "absent" if authority.optional else "missing-required"
                        entries.append(
                            Entry(
                                authority.name,
                                authority.source,
                                authority.kind,
                                authority.sensitive,
                                status,
                                None,
                                None,
                            )
                        )
                        continue
                    copy_authority(source, payload_path)
                entries.append(
                    Entry(
                        authority.name,
                        authority.source,
                        authority.kind,
                        authority.sensitive,
                        "captured",
                        payload_name,
                        hash_path(payload_path),
                        comparison_digest,
                    )
                )
            manifest = write_manifest(
                staging,
                entries,
                include_sensitive,
                registry,
                snapshot_epoch=snapshot_epoch,
                snapshot_started_at=snapshot_started_at,
                snapshot_completed_at=int(time.time()),
                quiesced_units=quiesced_units,
            )
            validate_staging_limits(staging)
            temporary_output = output.parent / f".{output.name}.{secrets.token_hex(6)}"
            try:
                with tarfile.open(temporary_output, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                    deterministic_tar_add(archive, staging / BUNDLE_MANIFEST, BUNDLE_MANIFEST)
                    deterministic_tar_add(archive, payload_root, PAYLOAD_ROOT)
                expanded_bundle_size(temporary_output)
                os.chmod(temporary_output, 0o600)
                os.replace(temporary_output, output)
                directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                temporary_output.unlink(missing_ok=True)
        return manifest
    finally:
        if unit_snapshot:
            restore_unit_state(unit_snapshot)


def safe_member_name(name: str) -> pathlib.PurePosixPath:
    if not isinstance(name, str) or not name:
        raise StateError("Unsafe bundle path: empty or non-text name")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise StateError("Unsafe bundle path: control character in member name")
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_ARCHIVE_MEMBER_NAME_BYTES:
        raise StateError("Unsafe bundle path: member name is too long")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise StateError(f"Unsafe bundle path: {name}")
    if any(len(part.encode("utf-8")) > MAX_ARCHIVE_COMPONENT_BYTES for part in path.parts):
        raise StateError("Unsafe bundle path: path component is too long")
    return path


def extract_bundle(bundle: pathlib.Path, destination: pathlib.Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    total = 0
    with tarfile.open(bundle, "r:*") as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise StateError("State bundle contains too many archive members")
        for member in members:
            normalized = safe_member_name(member.name).as_posix()
            if normalized in seen:
                raise StateError(f"State bundle contains duplicate path: {normalized}")
            seen.add(normalized)
            if not (member.isdir() or member.isreg()):
                raise StateError(f"State bundle contains unsupported archive object: {member.name}")
            total += max(0, member.size)
            if total > MAX_ARCHIVE_BYTES:
                raise StateError("State bundle exceeds the extraction size limit")
        for member in members:
            relative = safe_member_name(member.name)
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
                os.chmod(target, member.mode & 0o777)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise StateError(f"Unable to extract state member: {member.name}")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            fd = os.open(target, flags, member.mode & 0o777)
            try:
                with os.fdopen(fd, "wb") as handle:
                    shutil.copyfileobj(source, handle, length=1024 * 1024)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                source.close()
            os.chmod(target, member.mode & 0o777)


def _require_type(value: Any, expected: type, field: str) -> None:
    if expected is int and (not isinstance(value, int) or isinstance(value, bool)):
        raise StateError(f"State manifest field {field} has invalid type")
    if expected is not int and not isinstance(value, expected):
        raise StateError(f"State manifest field {field} has invalid type")


def load_extracted_manifest(staging: pathlib.Path) -> dict[str, Any]:
    try:
        manifest = json.loads((staging / BUNDLE_MANIFEST).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StateError("State bundle manifest is missing or invalid") from exc
    if not isinstance(manifest, dict):
        raise StateError("State bundle manifest must be an object")
    top_fields, entry_fields, allowed_statuses = manifest_contract()
    if set(manifest) != top_fields:
        raise StateError("State bundle top-level fields do not match the committed schema")
    _require_type(manifest["schemaVersion"], int, "schemaVersion")
    _require_type(manifest["registryVersion"], int, "registryVersion")
    _require_type(manifest["registryDigest"], str, "registryDigest")
    _require_type(manifest["producerVersion"], str, "producerVersion")
    _require_type(manifest["sourceRevision"], str, "sourceRevision")
    _require_type(manifest["createdAt"], int, "createdAt")
    _require_type(manifest["hostName"], str, "hostName")
    _require_type(manifest["snapshotEpoch"], str, "snapshotEpoch")
    _require_type(manifest["snapshotStartedAt"], int, "snapshotStartedAt")
    _require_type(manifest["snapshotCompletedAt"], int, "snapshotCompletedAt")
    _require_type(manifest["quiescedUnits"], list, "quiescedUnits")
    _require_type(manifest["includeSensitive"], bool, "includeSensitive")
    _require_type(manifest["complete"], bool, "complete")
    _require_type(manifest["signatureAlgorithm"], str, "signatureAlgorithm")
    _require_type(manifest["signature"], str, "signature")
    _require_type(manifest["entries"], list, "entries")
    if manifest["schemaVersion"] != SCHEMA_VERSION or manifest["registryVersion"] != REGISTRY_VERSION:
        raise StateError("Unsupported state bundle schema or registry version")
    if not re.fullmatch(r"[0-9a-f]{32}", manifest["snapshotEpoch"]):
        raise StateError("State bundle snapshot epoch is invalid")
    if manifest["snapshotCompletedAt"] < manifest["snapshotStartedAt"]:
        raise StateError("State bundle snapshot timestamps are invalid")
    if not all(isinstance(item, str) and item for item in manifest["quiescedUnits"]):
        raise StateError("State bundle quiesced unit list is invalid")
    if len(manifest["quiescedUnits"]) != len(set(manifest["quiescedUnits"])):
        raise StateError("State bundle quiesced unit list contains duplicates")
    if manifest["signatureAlgorithm"] != "hmac-sha256" or not DIGEST_RE.fullmatch(manifest["signature"]):
        raise StateError("State bundle signature metadata is invalid")
    if not compatible_version(manifest["producerVersion"], PRODUCER_VERSION):
        raise StateError(f"State bundle producer {manifest['producerVersion']} is incompatible with {PRODUCER_VERSION}")
    expected_signature = sign_manifest(manifest)
    if not hmac.compare_digest(manifest["signature"], expected_signature):
        raise StateError("State bundle signature verification failed")
    if not DIGEST_RE.fullmatch(manifest["registryDigest"]):
        raise StateError("State registry digest has invalid format")
    registry_items = authorities()
    expected_names = [item.name for item in registry_items]
    if manifest["registryDigest"] != registry_digest(registry_items):
        raise StateError("State bundle authority registry does not match this appliance")
    entries = manifest["entries"]
    if len(entries) != len(registry_items):
        raise StateError("State bundle does not contain the exact authority set")
    registry = {item.name: item for item in registry_items}
    seen: list[str] = []
    for raw in entries:
        if not isinstance(raw, dict) or set(raw) != entry_fields:
            raise StateError("State bundle entry fields do not match the committed schema")
        name = raw["name"]
        if not isinstance(name, str) or name not in registry or name in seen:
            raise StateError(f"State bundle has unknown or duplicate authority: {name}")
        seen.append(name)
        authority = registry[name]
        if (
            raw["source"] != authority.source
            or raw["kind"] != authority.kind
            or raw["sensitive"] != authority.sensitive
        ):
            raise StateError(f"State authority contract changed for {name}")
        if raw["status"] not in allowed_statuses:
            raise StateError(f"State authority {name} has invalid status")
        payload = raw["payload"]
        digest = raw["digest"]
        comparison_digest = raw["comparisonDigest"]
        if raw["status"] == "captured":
            if not isinstance(payload, str) or not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
                raise StateError(f"Captured authority is incomplete: {name}")
            if authority.kind == "database":
                if not isinstance(comparison_digest, str) or not DIGEST_RE.fullmatch(comparison_digest):
                    raise StateError(f"Database authority lacks a comparison digest: {name}")
            elif comparison_digest is not None:
                raise StateError(f"Path authority unexpectedly contains a comparison digest: {name}")
            payload_path = staging.joinpath(*safe_member_name(payload).parts)
            if lstat_type(payload_path) == 0 or hash_path(payload_path) != digest:
                raise StateError(f"State authority checksum failed: {name}")
        elif payload is not None or digest is not None or comparison_digest is not None:
            raise StateError(f"Uncaptured authority contains payload metadata: {name}")
        if raw["status"] == "absent" and not authority.optional:
            raise StateError(f"Required authority cannot be represented as absent: {name}")
        if raw["status"] == "omitted-sensitive" and not authority.sensitive:
            raise StateError(f"Non-sensitive authority cannot be omitted as sensitive: {name}")
    if seen != expected_names:
        raise StateError("State bundle authority order does not match the code-owned registry")
    computed_complete = all(item["status"] not in {"omitted-sensitive", "missing-required"} for item in entries)
    if manifest["complete"] is not computed_complete:
        raise StateError("State bundle completeness does not match its authority entries")
    if not manifest["includeSensitive"] and any(item["sensitive"] and item["status"] == "captured" for item in entries):
        raise StateError("State bundle captures sensitive state while includeSensitive is false")

    top_level = {item.name for item in staging.iterdir()}
    if top_level != {BUNDLE_MANIFEST, PAYLOAD_ROOT}:
        raise StateError("State bundle contains unmanifested top-level objects")
    payload_root = staging / PAYLOAD_ROOT
    if lstat_type(payload_root) == 0 or not stat.S_ISDIR(payload_root.lstat().st_mode):
        raise StateError("State bundle payload root is missing or invalid")
    expected_payloads = {item["name"] for item in entries if item["status"] == "captured"}
    actual_payloads = {item.name for item in payload_root.iterdir()}
    if actual_payloads != expected_payloads:
        raise StateError("State bundle payload set does not match the manifest")
    for item in entries:
        if item["status"] == "captured" and item["payload"] != f"{PAYLOAD_ROOT}/{item['name']}":
            raise StateError(f"State authority payload path is not canonical: {item['name']}")
    return manifest


def validate_bundle(bundle: pathlib.Path) -> dict[str, Any]:
    with state_temporary_directory("nas-state-validate.") as temporary:
        staging = pathlib.Path(temporary)
        extract_bundle(bundle, staging)
        return load_extracted_manifest(staging)


def compare_bundle(bundle: pathlib.Path) -> tuple[dict[str, Any], bool]:
    with state_temporary_directory("nas-state-diff.") as temporary:
        staging = pathlib.Path(temporary)
        extract_bundle(bundle, staging)
        manifest = load_extracted_manifest(staging)
        registry = {item.name: item for item in authorities()}
        rows: list[dict[str, Any]] = []
        overall = "match"
        for entry in manifest["entries"]:
            authority = registry[entry["name"]]
            status = entry["status"]
            comparison = "match"
            if status == "absent":
                exists = lstat_type(pathlib.Path(authority.source)) != 0 if authority.kind == "path" else True
                row_status = "drift" if exists else "match-absent"
            elif status != "captured":
                row_status = status
                comparison = "indeterminate"
            elif authority.kind == "database":
                current = database_comparison_digest()
                row_status = "match" if current == entry["comparisonDigest"] else "drift"
            else:
                source = pathlib.Path(authority.source)
                current = hash_path(source) if lstat_type(source) != 0 else None
                row_status = "match" if current == entry["digest"] else "drift"
            if row_status == "drift":
                comparison = "drift"
                overall = "drift"
            elif comparison == "indeterminate" and overall == "match":
                overall = "indeterminate"
            row: dict[str, Any] = {"name": authority.name, "status": row_status, "comparison": comparison}
            if status == "captured" and authority.kind == "path":
                row["currentDigest"] = current
            elif status == "captured" and authority.kind == "database":
                row["currentComparisonDigest"] = current
            rows.append(row)
        result = {
            "schemaVersion": SCHEMA_VERSION,
            "bundle": str(bundle),
            "result": overall,
            "drift": overall == "drift",
            "indeterminate": overall == "indeterminate",
            "authorities": rows,
        }
        return result, overall == "drift"


def run_systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = run_process(["systemctl", *arguments], timeout=600)
    if check and result.returncode != 0:
        raise StateError(f"systemctl operation failed: {' '.join(arguments)}")
    return result


def remove_path(path: pathlib.Path) -> None:
    mode = lstat_type(path)
    if mode == 0:
        return
    if stat.S_ISDIR(mode):
        shutil.rmtree(path)
    elif stat.S_ISREG(mode):
        path.unlink()
    else:
        raise StateError(f"Refusing to remove unsupported path: {path}")


def authority_root_policy(authority: Authority) -> PathPolicy:
    """Resolve the code-owned root ownership/mode for a path authority."""

    default_mode = 0o700 if authority.sensitive else 0o750
    if authority.owner is None or authority.group is None or authority.rootMode is None:
        # Direct-development fixtures may use the fallback registry. Installed
        # execution requires the generated registry with explicit ownership.
        return PathPolicy(0, 0, default_mode, authority.sensitive)
    try:
        uid = pwd.getpwnam(authority.owner).pw_uid
    except KeyError as exc:
        raise StateError(f"State authority {authority.name} owner does not exist: {authority.owner}") from exc
    try:
        gid = grp.getgrnam(authority.group).gr_gid
    except KeyError as exc:
        raise StateError(f"State authority {authority.name} group does not exist: {authority.group}") from exc
    return PathPolicy(uid, gid, int(authority.rootMode, 8), authority.sensitive)


def local_path_policies(destination: pathlib.Path, authority: Authority) -> dict[str, PathPolicy]:
    """Capture code-owned local ownership/modes without trusting archive owners."""

    policies: dict[str, PathPolicy] = {".": authority_root_policy(authority)}
    mode = lstat_type(destination)
    if not mode:
        return policies
    ensure_safe_tree(destination)
    root = destination.parent if stat.S_ISREG(mode) else destination
    items = [destination] if stat.S_ISREG(mode) else [destination, *sorted(destination.rglob("*"))]
    for item in items:
        metadata = item.lstat()
        key = "." if item == destination else item.relative_to(root).as_posix()
        policies[key] = PathPolicy(
            metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode) & 0o777, authority.sensitive
        )
    return policies


def _nearest_path_policy(relative: pathlib.PurePosixPath, policies: Mapping[str, PathPolicy]) -> PathPolicy:
    candidate = relative
    while True:
        key = "." if str(candidate) in {"", "."} else candidate.as_posix()
        if key in policies:
            return policies[key]
        if not candidate.parts:
            return policies["."]
        candidate = candidate.parent


def apply_local_path_policies(path: pathlib.Path, policies: Mapping[str, PathPolicy]) -> None:
    """Preserve existing heterogeneous ownership/modes and safely inherit for new paths."""

    ensure_safe_tree(path)
    root_is_file = stat.S_ISREG(path.lstat().st_mode)
    root = path.parent if root_is_file else path
    items = [path] if root_is_file else [path, *sorted(path.rglob("*"))]
    for item in items:
        metadata = item.lstat()
        relative = (
            pathlib.PurePosixPath(".") if item == path else pathlib.PurePosixPath(item.relative_to(root).as_posix())
        )
        key = "." if item == path else relative.as_posix()
        policy = policies.get(key) or _nearest_path_policy(relative.parent, policies)
        current = stat.S_IMODE(metadata.st_mode) & 0o777
        if key in policies:
            safe = policy.root_mode
        elif stat.S_ISDIR(metadata.st_mode):
            safe = (current & 0o775) | 0o700
        else:
            safe = (current & 0o664) | 0o600
        if policy.sensitive:
            safe &= 0o750 if stat.S_ISDIR(metadata.st_mode) else 0o640
        os.chmod(item, safe, follow_symlinks=False)
        if os.geteuid() == 0:
            os.chown(item, policy.uid, policy.gid, follow_symlinks=False)


def restore_path(source: pathlib.Path, destination: pathlib.Path, authority: Authority) -> None:
    ensure_safe_tree(source)
    policies = local_path_policies(destination, authority)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.nas-state-{secrets.token_hex(6)}"
    backup: pathlib.Path | None = None
    try:
        copy_authority(source, temporary)
        apply_local_path_policies(temporary, policies)
        if lstat_type(destination) != 0:
            if stat.S_ISLNK(destination.lstat().st_mode):
                raise StateError(f"Refusing to replace symlink destination: {destination}")
            backup = destination.parent / f".{destination.name}.nas-state-old-{secrets.token_hex(6)}"
            os.replace(destination, backup)
        try:
            os.replace(temporary, destination)
        except Exception:
            if backup is not None and lstat_type(backup) != 0 and lstat_type(destination) == 0:
                os.replace(backup, destination)
            raise
        if backup is not None:
            remove_path(backup)
    finally:
        if lstat_type(temporary) != 0:
            remove_path(temporary)


def canonical_apply_entries(manifest: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    by_name = {item["name"]: item for item in manifest["entries"]}
    return [by_name[authority.name] for authority in authorities()]


def apply_extracted(staging: pathlib.Path, manifest: dict[str, Any], *, restore_absence: bool = False) -> None:
    registry = {item.name: item for item in authorities()}
    for entry in canonical_apply_entries(manifest):
        authority = registry[entry["name"]]
        if entry["status"] == "absent":
            destination = pathlib.Path(authority.source)
            if authority.kind == "path" and lstat_type(destination) != 0:
                if not restore_absence:
                    raise StateError(f"Restoring absence for {authority.name} requires --restore-absence")
                remove_path(destination)
            continue
        if entry["status"] != "captured":
            continue
        payload = staging.joinpath(*safe_member_name(entry["payload"]).parts)
        if authority.kind == "database":
            restore_database(payload)
        else:
            restore_path(payload, pathlib.Path(authority.source), authority)


def restore_units() -> tuple[str, ...]:
    raw = os.environ.get("NAS_STATE_RESTORE_UNITS_JSON")
    if raw:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StateError("NAS_STATE_RESTORE_UNITS_JSON is invalid") from exc
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise StateError("NAS_STATE_RESTORE_UNITS_JSON must be an array of unit names")
        return tuple(dict.fromkeys(value))
    return (
        "nas-protected-services.target",
        "nas-identity-sync.timer",
        "NetworkManager.service",
        "firewalld.service",
    )


def capture_unit_state(units: Iterable[str]) -> dict[str, bool]:
    return {unit: run_systemctl("is-active", "--quiet", unit, check=False).returncode == 0 for unit in units}


def stop_active_units(snapshot: Mapping[str, bool]) -> None:
    """Quiesce active units; restore already-stopped units if quiescing fails."""

    stopped: list[str] = []
    try:
        for unit, active in reversed(list(snapshot.items())):
            if active:
                run_systemctl("stop", unit)
                stopped.append(unit)
    except Exception as original:
        recovery_errors: list[str] = []
        for unit in reversed(stopped):
            try:
                run_systemctl("start", unit)
            except Exception as exc:  # retain every failed recovery action
                recovery_errors.append(f"{unit}: {exc}")
        if recovery_errors:
            raise StateError(
                "Quiesce failed and previously stopped units could not all be restored: " + "; ".join(recovery_errors)
            ) from original
        raise


def restore_unit_state(snapshot: Mapping[str, bool]) -> None:
    for unit, active in snapshot.items():
        currently_active = run_systemctl("is-active", "--quiet", unit, check=False).returncode == 0
        if active and not currently_active:
            run_systemctl("start", unit)
        elif not active and currently_active:
            run_systemctl("stop", unit)


def secure_rollback_root() -> None:
    mode = lstat_type(DEFAULT_ROLLBACK_ROOT)
    if mode and (stat.S_ISLNK(mode) or not stat.S_ISDIR(mode)):
        raise StateError(f"Rollback root is not a trusted directory: {DEFAULT_ROLLBACK_ROOT}")
    DEFAULT_ROLLBACK_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DEFAULT_ROLLBACK_ROOT, 0o700)
    if os.geteuid() == 0:
        os.chown(DEFAULT_ROLLBACK_ROOT, 0, 0)


def prune_rollbacks() -> None:
    now = time.time()
    candidates = sorted(
        DEFAULT_ROLLBACK_ROOT.glob("rollback-*.tar.gz"), key=lambda item: item.stat().st_mtime, reverse=True
    )
    for index, item in enumerate(candidates):
        too_old = ROLLBACK_RETAIN_SECONDS and now - item.stat().st_mtime > ROLLBACK_RETAIN_SECONDS
        if index >= ROLLBACK_RETAIN_COUNT or too_old:
            item.unlink(missing_ok=True)


def require_free_space(path: pathlib.Path, required: int) -> None:
    usage = shutil.disk_usage(path)
    if usage.free < required:
        raise StateError(f"Insufficient free space under {path}; need at least {required} bytes")


def reapply_runtime_consumers(snapshot: Mapping[str, bool]) -> None:
    """Restore service state before reloading consumers of restored files.

    NetworkManager and firewalld may be part of the restore quiesce set. Reloading
    an inactive unit fails, so bring originally-active consumers back first and
    only then ask them to re-read restored configuration. The generated restore
    unit list makes this profile-aware in installed execution.
    """

    run_systemctl("daemon-reload")

    for unit in ("NetworkManager.service", "firewalld.service"):
        if snapshot.get(unit, False):
            currently_active = run_systemctl("is-active", "--quiet", unit, check=False).returncode == 0
            if not currently_active:
                run_systemctl("start", unit)

    if snapshot.get("NetworkManager.service", False):
        # Reload connection profiles explicitly. `systemctl reload NetworkManager`
        # reloads daemon configuration but does not guarantee that restored
        # system-connections are re-read into NetworkManager's runtime state.
        result = run_process(["nmcli", "connection", "reload"], timeout=60)
        if result.returncode != 0:
            raise StateError("NetworkManager connection profile reload failed")
        run_systemctl("reload", "NetworkManager.service")
    if snapshot.get("firewalld.service", False):
        run_systemctl("reload", "firewalld.service")

    restore_unit_state(snapshot)


def expanded_bundle_size(bundle: pathlib.Path) -> int:
    try:
        with tarfile.open(bundle, "r:*") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        raise StateError(f"Unable to inspect state bundle: {bundle}") from exc
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise StateError("State bundle contains too many archive members")
    total = sum(max(0, item.size) for item in members)
    if total > MAX_ARCHIVE_BYTES:
        raise StateError("State bundle exceeds the extraction size limit")
    return total


def restore_journal_update(status: str, **fields: Any) -> None:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "workflow": "state-restore",
        "status": status,
        "updatedAt": int(time.time()),
    }
    try:
        previous = json.loads(RESTORE_JOURNAL.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        previous = {}
    if isinstance(previous, dict):
        value = {**previous, **value}
    value.update(fields)
    atomic_write_json(RESTORE_JOURNAL, value, mode=0o600)


def rollback_inventory() -> dict[str, Any]:
    secure_rollback_root()
    bundles = []
    for item in sorted(
        DEFAULT_ROLLBACK_ROOT.glob("rollback-*.tar.gz"), key=lambda path: path.stat().st_mtime, reverse=True
    ):
        metadata = item.stat()
        bundles.append({"path": str(item), "bytes": metadata.st_size, "modifiedAt": int(metadata.st_mtime)})
    return {
        "root": str(DEFAULT_ROLLBACK_ROOT),
        "retentionCount": ROLLBACK_RETAIN_COUNT,
        "retentionSeconds": ROLLBACK_RETAIN_SECONDS,
        "bundles": bundles,
    }


def restore_bundle(
    bundle: pathlib.Path,
    *,
    confirm_host: str,
    allow_partial: bool,
    include_sensitive: bool,
    restore_absence: bool = False,
) -> dict[str, Any]:
    require_root()
    secure_rollback_root()
    expanded = expanded_bundle_size(bundle)
    temp_root = runtime_root()
    require_free_space(temp_root, max(expanded * 2, 64 * 1024 * 1024))
    require_free_space(DEFAULT_ROLLBACK_ROOT, max(expanded + bundle.stat().st_size * 3, 128 * 1024 * 1024))
    restore_id = secrets.token_hex(12)
    restore_journal_update(
        "preparing",
        restoreId=restore_id,
        bundle=str(bundle),
        startedAt=int(time.time()),
        expandedBytes=expanded,
        rollbackBundle=None,
        errors=[],
    )
    with state_temporary_directory("nas-state-restore.") as temporary:
        staging = pathlib.Path(temporary)
        extract_bundle(bundle, staging)
        manifest = load_extracted_manifest(staging)
        current_host = socket.gethostname()
        if confirm_host != current_host or manifest["hostName"] != current_host:
            raise StateError("Restore confirmation and bundle hostname must match this host")
        if not manifest["complete"] and not allow_partial:
            raise StateError("Partial bundles require --allow-partial")
        if (
            any(entry["sensitive"] and entry["status"] == "captured" for entry in manifest["entries"])
            and not include_sensitive
        ):
            raise StateError("Sensitive bundle restore requires --include-sensitive")
        prune_rollbacks()
        rollback = DEFAULT_ROLLBACK_ROOT / f"rollback-{int(time.time())}-{secrets.token_hex(4)}.tar.gz"
        unit_snapshot = capture_unit_state(restore_units())
        stop_active_units(unit_snapshot)
        restore_journal_update("quiesced", unitSnapshot=unit_snapshot)
        rollback_ready = False
        try:
            # The appliance is already quiesced. Capture rollback state once without
            # an additional stop/start cycle before applying the requested bundle.
            export_bundle(rollback, include_sensitive=True, quiesce=False)
            rollback_ready = True
            restore_journal_update("rollback-captured", rollbackBundle=str(rollback))
            apply_extracted(staging, manifest, restore_absence=restore_absence)
            restore_journal_update("state-applied")
            reapply_runtime_consumers(unit_snapshot)
            restore_journal_update("committed", completedAt=int(time.time()))
        except Exception as original:
            if not rollback_ready:
                try:
                    restore_unit_state(unit_snapshot)
                except Exception as unit_error:
                    restore_journal_update(
                        "manual-recovery-required",
                        primaryError=str(original),
                        rollbackError=f"rollback capture failed before state apply; unit recovery failed: {unit_error}",
                        completedAt=int(time.time()),
                    )
                    raise StateError(
                        f"Restore preparation failed and service recovery also failed: {unit_error}"
                    ) from original
                restore_journal_update("failed-before-apply", primaryError=str(original), completedAt=int(time.time()))
                raise
            restore_journal_update("rolling-back", primaryError=str(original))
            try:
                with state_temporary_directory("nas-state-rollback.") as rollback_temp:
                    rollback_staging = pathlib.Path(rollback_temp)
                    extract_bundle(rollback, rollback_staging)
                    rollback_manifest = load_extracted_manifest(rollback_staging)
                    apply_extracted(rollback_staging, rollback_manifest, restore_absence=True)
                reapply_runtime_consumers(unit_snapshot)
                restore_journal_update("failed-rolled-back", completedAt=int(time.time()))
            except Exception as rollback_error:
                restore_journal_update(
                    "manual-recovery-required", rollbackError=str(rollback_error), completedAt=int(time.time())
                )
                raise StateError(
                    f"Restore failed and automatic rollback also failed; recover from {rollback}: {rollback_error}"
                ) from original
            raise
        prune_rollbacks()
        return {"ok": True, "restoreId": restore_id, "rollbackBundle": str(rollback), "restored": str(bundle)}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="nas-state",
        description="Export, compare, validate, and restore NAS control-plane state bundles.",
    )
    subparsers = result.add_subparsers(dest="command", required=True)
    export = subparsers.add_parser("export", help="Create a validated state bundle")
    export.add_argument("output", type=pathlib.Path, help="Destination bundle path")
    export.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Include state classified as sensitive when policy permits it",
    )
    validate = subparsers.add_parser("validate", help="Validate a bundle without changing the system")
    validate.add_argument("bundle", type=pathlib.Path, help="Bundle to validate")
    diff = subparsers.add_parser("diff", help="Compare a bundle with current managed state")
    diff.add_argument("bundle", type=pathlib.Path, help="Bundle to compare")
    diff.add_argument("--json", action="store_true", help="Emit the comparison as JSON")
    restore = subparsers.add_parser("restore", help="Restore a validated bundle with rollback protection")
    restore.add_argument("bundle", type=pathlib.Path, help="Bundle to restore")
    restore.add_argument(
        "--apply", action="store_true", help="Perform the restore instead of refusing a dry invocation"
    )
    restore.add_argument("--confirm-host", required=True, help="Expected host identity required before restore")
    restore.add_argument(
        "--allow-partial", action="store_true", help="Allow authorities that explicitly support partial restore"
    )
    restore.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Restore sensitive state included in the bundle when policy permits it",
    )
    restore.add_argument(
        "--restore-absence",
        action="store_true",
        help="Remove managed state that is intentionally absent from the bundle",
    )
    subparsers.add_parser("authorities", help="List registered state authorities")
    subparsers.add_parser("rollbacks", help="List retained automatic rollback bundles")
    subparsers.add_parser("prune-rollbacks", help="Prune expired rollback bundles")
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        if args.command == "export":
            token = os.environ.get(COORDINATION_TOKEN_ENV)
            if token:
                validate_coordination_token(token, ("appliance",))
                value = export_bundle(args.output, include_sensitive=args.include_sensitive)
            else:
                # A state bundle spans multiple mutable authorities. Hold the
                # appliance-wide coordinator so custom writers cannot race the
                # quiesced service snapshot.
                with acquire_operation("state-export", ("appliance",)):
                    value = export_bundle(args.output, include_sensitive=args.include_sensitive)
        elif args.command == "validate":
            value = validate_bundle(args.bundle)
        elif args.command == "diff":
            value, drift = compare_bundle(args.bundle)
            if args.json:
                print(json.dumps(value, indent=2, sort_keys=True))
            else:
                for row in value["authorities"]:
                    print(f"{row['name']}: {row['status']}")
                print(f"overall: {value['result']}")
            raise SystemExit(1 if drift else 2 if value["indeterminate"] else 0)
        elif args.command == "restore":
            if not args.apply:
                raise StateError("Restore requires --apply")
            restore_arguments = dict(
                confirm_host=args.confirm_host,
                allow_partial=args.allow_partial,
                include_sensitive=args.include_sensitive,
                restore_absence=args.restore_absence,
            )
            token = os.environ.get(COORDINATION_TOKEN_ENV)
            if token:
                validate_coordination_token(token, ("appliance",))
                value = restore_bundle(args.bundle, **restore_arguments)
            else:
                with acquire_operation("state-restore", ("appliance",)):
                    value = restore_bundle(args.bundle, **restore_arguments)
        elif args.command == "rollbacks":
            value = rollback_inventory()
        elif args.command == "prune-rollbacks":
            secure_rollback_root()
            before = rollback_inventory()
            prune_rollbacks()
            value = {"before": before, "after": rollback_inventory()}
        else:
            registry = authorities()
            value = {
                "schemaVersion": SCHEMA_VERSION,
                "registryVersion": REGISTRY_VERSION,
                "registryDigest": registry_digest(registry),
                "authorities": [asdict(item) for item in registry],
            }
        print(json.dumps(value, indent=2, sort_keys=True))
    except (StateError, OperationBusyError) as exc:
        print(f"nas-state: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
