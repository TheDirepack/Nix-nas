#!/usr/bin/env python3
"""Allow-listed privileged backend for the Cockpit NAS page."""

from __future__ import annotations

import argparse
import contextlib
import concurrent.futures
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import stat
import sys
import syslog
import tempfile
from dataclasses import dataclass
from typing import Any

from nas_common import CommandResult, parse_systemd_show, run_command
import nas_ai_config as ai_config
from nas_operation_lock import (
    OperationBusyError,
    acquire_operation,
    cancel_reservation,
    operation_state as shared_operation_state,
    reserve_operation,
)

ZFS_POOL = os.environ.get("NAS_ZFS_POOL", "tank")
ZFS_DATASET = os.environ.get("NAS_ZFS_DATASET", "tank/nas")
CONFIG_DIR = pathlib.Path(os.environ.get("NAS_CONFIG_DIR", "/etc/nixos/nixos-nas"))
ENDPOINT_REGISTRY = pathlib.Path(os.environ.get("NAS_ENDPOINT_REGISTRY", "/etc/nas-control/endpoints.json"))
BACKUP_INSTALLED = os.environ.get("NAS_BACKUP_ENABLE", "0") == "1"
ZFS_REPLICATION_INSTALLED = os.environ.get("NAS_ZFS_REPLICATION_ENABLE", "0") == "1"
SYNCTHING_INSTALLED = os.environ.get("NAS_SYNCTHING_ENABLE", "0") == "1"
FIRST_RUN_CONFIG = os.environ.get("NAS_FIRST_RUN_CONFIG", "/etc/nixos/nixos-nas/first-run.json")
MAX_PASSWORD_LENGTH = 4096
FIRST_START_CONFLICTS = ("appliance", "first-start", "identity", "runtime", "secrets", "state", "storage", "update")

FEATURE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
MAX_ARGUMENT_LENGTH = 128
MAX_JSON_INPUT_BYTES = 128 * 1024
MAX_PRIVATE_SNAPSHOT_BYTES = 4 * 1024 * 1024


class ApiError(RuntimeError):
    """Expected appliance operation failure."""


@dataclass(frozen=True)
class ActionSpec:
    commands: tuple[tuple[str, ...], ...]
    timeout_seconds: int = 300
    conflicts: tuple[str, ...] = ("runtime",)
    requires_backup: bool = False
    requires_replication: bool = False
    requires_syncthing: bool = False
    worker_owns_operation: bool = False


@dataclass(frozen=True)
class PrivateFileSnapshot:
    exists: bool
    content: bytes = b""
    mode: int = 0o600
    uid: int = 0
    gid: int = 0


ACTIONS: dict[str, ActionSpec] = {
    "identity-sync": ActionSpec(
        (("systemctl", "start", "nas-identity-sync.service"),),
        conflicts=("identity",),
        worker_owns_operation=True,
    ),
    "health": ActionSpec(
        (
            (
                "systemctl",
                "start",
                "nas-zfs-pool-health.service",
                "nas-zfs-capacity-health.service",
                "nas-zfs-snapshot-health.service",
            ),
        ),
        conflicts=("storage",),
    ),
    "snapshot": ActionSpec(
        (("systemctl", "start", "nas-zfs-manual-snapshot.service"),),
        conflicts=("storage",),
    ),
    "scrub": ActionSpec(
        (("systemctl", "start", "nas-zfs-manual-scrub.service"),),
        conflicts=("storage",),
    ),
    "backup": ActionSpec(
        (("systemctl", "start", "restic-backups-nas-boot-system.service"),),
        conflicts=("storage",),
        requires_backup=True,
    ),
    "zfs-replicate": ActionSpec(
        (("systemctl", "start", "nas-syncoid.service"),),
        conflicts=("storage",),
        requires_replication=True,
    ),
    "update-preview": ActionSpec(
        (("systemctl", "start", "nas-update-preview.service"),),
        timeout_seconds=600,
        conflicts=("update",),
        worker_owns_operation=True,
    ),
    "update-sync": ActionSpec(
        (("systemctl", "start", "nas-update-sync.service"),),
        timeout_seconds=21600,
        conflicts=("update",),
        worker_owns_operation=True,
    ),
    "update-apply": ActionSpec(
        (("systemctl", "start", "nas-update-apply.service"),),
        timeout_seconds=21600,
        conflicts=("identity", "runtime", "storage", "update"),
        worker_owns_operation=True,
    ),
    "protected-restart": ActionSpec(
        (("systemctl", "start", "nas-protected-restart.service"),),
        conflicts=("identity", "runtime"),
        worker_owns_operation=True,
    ),
    "syncthing-reconcile": ActionSpec(
        (("systemctl", "start", "nas-syncthing-sync.service"),),
        conflicts=("identity",),
        requires_syncthing=True,
        worker_owns_operation=True,
    ),
}


def operation_state() -> dict[str, Any]:
    value = shared_operation_state()
    value.update(
        {
            "conflictsByAction": {name: list(spec.conflicts) for name, spec in ACTIONS.items()},
            "workerOwnedActions": [name for name, spec in ACTIONS.items() if spec.worker_owns_operation],
            "featureConflicts": ["runtime"],
            "firstStartConflicts": ["appliance", "first-start", "identity", "runtime", "storage", "update"],
        }
    )
    return value


@contextlib.contextmanager
def operation_guard(action: str, conflicts: tuple[str, ...]):
    try:
        with acquire_operation(action, conflicts):
            yield
    except OperationBusyError as exc:
        raise ApiError(str(exc)) from exc


def diagnostic(message: str) -> None:
    syslog.syslog(syslog.LOG_ERR, message[:2000])


def _secret_command(command: list[str] | tuple[str, ...]) -> bool:
    if not command:
        return False
    return pathlib.PurePath(str(command[0])).name == "nas-secrets"


def operation_error(command: list[str] | tuple[str, ...], result: CommandResult) -> ApiError:
    reference = secrets.token_hex(6)
    if _secret_command(command):
        detail = "[secret command output redacted]"
    else:
        detail = (result.stderr or result.stdout).strip()[:1000]
    diagnostic(
        f"nas-cockpit-api reference={reference} command={list(command)!r} rc={result.returncode} detail={detail!r}"
    )
    return ApiError(f"Operation failed (reference {reference})")


def run(
    cmd: list[str] | tuple[str, ...],
    *,
    check: bool = True,
    timeout_seconds: int = 120,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    command = list(cmd)
    result = run_command(
        command,
        timeout_seconds=timeout_seconds,
        input_text=input_text,
        env=env,
    )
    if check and result.returncode != 0:
        raise operation_error(command, result)
    return result


def json_command(
    cmd: list[str],
    *,
    optional: bool = False,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    proc = run(cmd, check=False, timeout_seconds=timeout_seconds)
    if proc.returncode != 0:
        error = operation_error(cmd, proc)
        if optional:
            return {"ok": False, "error": str(error)}
        raise error
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ApiError(f"{' '.join(cmd)} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ApiError(f"{' '.join(cmd)} returned a non-object JSON value")
    return value


def validate_argument(value: str, pattern: re.Pattern[str], label: str) -> str:
    if len(value) > MAX_ARGUMENT_LENGTH or not pattern.fullmatch(value):
        raise ApiError(f"Invalid {label}")
    return value


def service_states(units: list[str]) -> list[dict[str, str]]:
    if not units:
        return []
    proc = run(
        [
            "systemctl",
            "show",
            "--property=Id,LoadState,ActiveState,SubState,UnitFileState",
            *units,
        ],
        check=False,
        timeout_seconds=30,
    )
    records = {
        unit: {
            "unit": unit,
            "active": values.get("ActiveState", "unknown"),
            "enabled": values.get("UnitFileState", "unknown"),
            "sub": values.get("SubState", "unknown"),
            "load": values.get("LoadState", "unknown"),
        }
        for unit, values in parse_systemd_show(proc.stdout).items()
    }
    return [
        records.get(
            unit, {"unit": unit, "active": "unknown", "enabled": "unknown", "sub": "unknown", "load": "unknown"}
        )
        for unit in units
    ]


def feature_status() -> dict[str, Any]:
    return json_command(["nas-feature-control", "status"], optional=True)


def identity_status() -> dict[str, Any]:
    return json_command(["nas-identity-sync", "status"], optional=True)


def capability_status() -> dict[str, Any]:
    return json_command(["nas-identity-sync", "capabilities"], optional=True)


def update_status() -> dict[str, Any]:
    return json_command(["nas-update", "--status", "--json"], optional=True)


def setup_status() -> dict[str, Any]:
    prepared = json_command(
        ["nas-setup", "prepare-first-start", "--config", FIRST_RUN_CONFIG],
        optional=True,
    )
    status = json_command(["nas-setup", "status"], optional=True)
    if prepared.get("ok") is False and "firstStart" not in status:
        status["firstStart"] = prepared
    return status


def read_optional_text(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None


def endpoint_links(path: pathlib.Path = ENDPOINT_REGISTRY) -> dict[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(payload, dict) or payload.get("schemaVersion") != 1:
        return {}
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, dict):
        return {}
    links: dict[str, str] = {}
    for value in endpoints.values():
        if not isinstance(value, dict) or value.get("available") is not True:
            continue
        key = value.get("linkKey")
        public_path = value.get("publicPath")
        if (
            isinstance(key, str)
            and key
            and isinstance(public_path, str)
            and public_path.startswith("/")
            and not public_path.startswith("//")
            and not any(ord(character) < 32 or ord(character) == 127 for character in public_path)
        ):
            links[key] = public_path
    return links


def read_json_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_JSON_INPUT_BYTES + 1)
    if len(raw) > MAX_JSON_INPUT_BYTES:
        raise ApiError("Request body is too large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError("Request body must be a JSON object") from exc
    if not isinstance(value, dict):
        raise ApiError("Request body must be a JSON object")
    return value


def ai_configuration() -> dict[str, Any]:
    try:
        return ai_config.public_view(ai_config.load_config())
    except (ai_config.AiConfigError, OSError) as exc:
        return {"ok": False, "error": str(exc), "providers": [], "codingRoles": {}, "availableTargets": []}


def _json_string(request: dict[str, Any], key: str, *, required: bool = False, max_length: int = 4096) -> str:
    value = request.get(key, "")
    if not isinstance(value, str) or len(value) > max_length or "\x00" in value:
        raise ApiError(f"Invalid {key}")
    if required and not value:
        raise ApiError(f"{key} is required")
    return value


def _json_string_list(request: dict[str, Any], key: str, *, required: bool = False) -> list[str]:
    value = request.get(key, [])
    if not isinstance(value, list) or len(value) > ai_config.MAX_MODELS or any(not isinstance(item, str) for item in value):
        raise ApiError(f"Invalid {key}")
    if required and not value:
        raise ApiError(f"{key} is required")
    return value


def _coordinated_secret_command(active: Any, command: list[str], input_text: str) -> None:
    env = dict(os.environ)
    env["NAS_OPERATION_COORDINATION_TOKEN"] = active.coordination_token
    result = run(command, check=False, timeout_seconds=120, input_text=input_text, env=env)
    if result.returncode != 0:
        raise operation_error(command, result)


def _snapshot_private_file(path: pathlib.Path, label: str) -> PrivateFileSnapshot:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return PrivateFileSnapshot(False)
    except OSError as exc:
        raise ApiError(f"Unable to snapshot {label}") from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ApiError(f"Refusing unsafe {label} path")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ApiError(f"Unable to snapshot {label}") from exc
    try:
        current = os.fstat(fd)
        if current.st_dev != before.st_dev or current.st_ino != before.st_ino or not stat.S_ISREG(current.st_mode):
            raise ApiError(f"{label} changed while it was being snapshotted")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            content = handle.read(MAX_PRIVATE_SNAPSHOT_BYTES + 1)
        if len(content) > MAX_PRIVATE_SNAPSHOT_BYTES:
            raise ApiError(f"{label} is unexpectedly large")
        return PrivateFileSnapshot(
            True,
            content,
            stat.S_IMODE(current.st_mode),
            current.st_uid,
            current.st_gid,
        )
    finally:
        if fd >= 0:
            os.close(fd)


def _fsync_parent(path: pathlib.Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _restore_private_file(path: pathlib.Path, snapshot: PrivateFileSnapshot, label: str) -> None:
    parent = path.parent
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise ApiError(f"Unable to restore {label}: parent directory unavailable") from exc
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
        raise ApiError(f"Unable to restore {label}: unsafe parent directory")
    if not snapshot.exists:
        try:
            path.unlink(missing_ok=True)
            _fsync_parent(path)
        except OSError as exc:
            raise ApiError(f"Unable to restore absent {label}") from exc
        return
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.rollback.", dir=parent)
    temporary_path = pathlib.Path(temporary)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(snapshot.content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, snapshot.mode)
        if os.geteuid() == 0:
            os.chown(temporary_path, snapshot.uid, snapshot.gid)
        os.replace(temporary_path, path)
        replaced = True
        _fsync_parent(path)
    except OSError as exc:
        raise ApiError(f"Unable to restore {label}") from exc
    finally:
        if not replaced:
            temporary_path.unlink(missing_ok=True)


def _secret_env_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("NAS_SECRET_ROOT", "/run/nas-secrets")) / "ai" / "llama-swap.env"


def _read_secret_env() -> bytes | None:
    snapshot = _snapshot_private_file(_secret_env_path(), "llama-swap runtime secret environment")
    return snapshot.content if snapshot.exists else None


def _restore_secret_env(content: bytes | None, active: Any) -> None:
    del active
    path = _secret_env_path()
    if content is None:
        return
    try:
        current = _snapshot_private_file(path, "llama-swap runtime secret environment")
        snapshot = PrivateFileSnapshot(True, content, current.mode if current.exists else 0o400, current.uid, current.gid)
        _restore_private_file(path, snapshot, "llama-swap runtime secret environment")
    except ApiError:
        raise


def _provider_reference_configured(config: dict[str, Any], provider_id: str) -> bool:
    peers = config.get("peers")
    if not isinstance(peers, dict):
        return False
    peer = peers.get(provider_id)
    if not isinstance(peer, dict):
        return False
    expected = "${env." + ai_config.provider_env_name(provider_id) + "}"
    return peer.get("apiKey") == expected


def _fetch_existing_provider_key(active: Any, provider_id: str, keepass_password: str) -> str:
    fetch_env = dict(os.environ)
    fetch_env["NAS_OPERATION_COORDINATION_TOKEN"] = active.coordination_token
    command = ["nas-secrets", "show-ai-provider-key-stdin", provider_id]
    result = run(
        command,
        check=False,
        timeout_seconds=30,
        input_text=f"{keepass_password}\n",
        env=fetch_env,
    )
    if result.returncode != 0:
        diagnostic(f"nas-cockpit-api unable to snapshot existing provider credential id={provider_id!r} rc={result.returncode}")
        raise ApiError("Unable to snapshot the existing provider credential before mutation")
    value = result.stdout.strip()
    if not value or len(value) > 4096 or "\n" in value or "\r" in value or "\x00" in value:
        raise ApiError("Existing provider credential is missing or malformed; refusing mutation")
    return value


def _write_provider_key(active: Any, provider_id: str, keepass_password: str, value: str | None) -> None:
    env = dict(os.environ)
    env["NAS_OPERATION_COORDINATION_TOKEN"] = active.coordination_token
    env["NAS_SKIP_LLAMA_SWAP_RESTART"] = "1"
    if value is None:
        command = ["nas-secrets", "clear-ai-provider-key-stdin", provider_id]
        input_text = f"{keepass_password}\n"
    else:
        command = ["nas-secrets", "set-ai-provider-key-stdin", provider_id]
        input_text = f"{keepass_password}\n{value}\n"
    result = run(command, check=False, timeout_seconds=120, input_text=input_text, env=env)
    if result.returncode != 0:
        raise operation_error(command, result)


def _llama_swap_active(active: Any) -> bool:
    env = dict(os.environ)
    env["NAS_OPERATION_COORDINATION_TOKEN"] = active.coordination_token
    result = run(
        ["systemctl", "is-active", "--quiet", "nas-llama-swap.service"],
        check=False,
        timeout_seconds=10,
        env=env,
    )
    return result.returncode == 0


def _restart_llama_swap(active: Any, *, was_active: bool | None = None) -> None:
    env = dict(os.environ)
    env["NAS_OPERATION_COORDINATION_TOKEN"] = active.coordination_token
    should_restart = _llama_swap_active(active) if was_active is None else was_active
    if not should_restart:
        return
    result = run(
        ["systemctl", "restart", "nas-llama-swap.service"],
        check=False,
        timeout_seconds=60,
        env=env,
    )
    if result.returncode != 0:
        raise operation_error(["systemctl", "restart", "nas-llama-swap.service"], result)
    result = run(
        ["systemctl", "is-active", "--quiet", "nas-llama-swap.service"],
        check=False,
        timeout_seconds=10,
        env=env,
    )
    if result.returncode != 0:
        raise ApiError("llama-swap failed to start after provider update")


def _rollback_provider_mutation(
    *,
    active: Any,
    provider_id: str,
    keepass_password: str,
    old_config: PrivateFileSnapshot,
    old_env: PrivateFileSnapshot | None,
    had_credential: bool,
    old_keepass_key: str | None,
    credential_attempted: bool,
    config_attempted: bool,
    service_was_active: bool,
) -> None:
    failures: list[str] = []
    if credential_attempted:
        try:
            _write_provider_key(
                active,
                provider_id,
                keepass_password,
                old_keepass_key if had_credential else None,
            )
        except Exception:
            failures.append("KeePass credential")
    if old_env is not None:
        try:
            _restore_private_file(_secret_env_path(), old_env, "llama-swap runtime secret environment")
        except Exception:
            failures.append("runtime secret environment")
    if config_attempted:
        try:
            _restore_private_file(pathlib.Path(ai_config.CONFIG_PATH), old_config, "llama-swap configuration")
        except Exception:
            failures.append("llama-swap configuration")
    if service_was_active:
        try:
            _restart_llama_swap(active, was_active=True)
        except Exception:
            failures.append("llama-swap service")
    if failures:
        diagnostic("nas-cockpit-api provider rollback incomplete components=" + ",".join(failures))
        raise ApiError("Provider mutation failed and rollback was incomplete; manual recovery is required")


def set_ai_provider(request: dict[str, Any]) -> dict[str, Any]:
    provider_id = _json_string(request, "id", required=True, max_length=48)
    url = _json_string(request, "url", required=True, max_length=2048)
    models = _json_string_list(request, "models", required=True)
    api_key = _json_string(request, "apiKey", max_length=4096)
    keepass_password = _json_string(request, "keepassPassword", max_length=MAX_PASSWORD_LENGTH)
    timeouts = request.get("timeouts", {})
    filters = request.get("filters", {})
    try:
        ai_config.validate_provider_id(provider_id)
        ai_config.validate_proxy_url(url)
        ai_config.validate_models(models)
        ai_config.validate_timeouts(timeouts)
        ai_config.validate_filters(filters)
    except ai_config.AiConfigError as exc:
        raise ApiError(str(exc)) from exc
    if api_key and not keepass_password:
        raise ApiError("KeePassXC database password is required when setting a provider API key")
    if "\n" in keepass_password or "\r" in keepass_password or "\n" in api_key or "\r" in api_key:
        raise ApiError("Provider credentials must be single-line values")

    old_keepass_key: str | None = None
    try:
        with acquire_operation("ai-provider-set", ("secrets", "runtime")) as active:
            old_config = _snapshot_private_file(pathlib.Path(ai_config.CONFIG_PATH), "llama-swap configuration")
            before = ai_config.load_config()
            had_credential = _provider_reference_configured(before, provider_id)
            old_env: PrivateFileSnapshot | None = None
            credential_attempted = False
            config_attempted = False
            service_was_active = _llama_swap_active(active)
            if api_key:
                old_env = _snapshot_private_file(_secret_env_path(), "llama-swap runtime secret environment")
                if had_credential:
                    old_keepass_key = _fetch_existing_provider_key(active, provider_id, keepass_password)
                try:
                    credential_attempted = True
                    _write_provider_key(active, provider_id, keepass_password, api_key)
                except Exception as original:
                    try:
                        _rollback_provider_mutation(
                            active=active,
                            provider_id=provider_id,
                            keepass_password=keepass_password,
                            old_config=old_config,
                            old_env=old_env,
                            had_credential=had_credential,
                            old_keepass_key=old_keepass_key,
                            credential_attempted=credential_attempted,
                            config_attempted=False,
                            service_was_active=False,
                        )
                    except ApiError as rollback_error:
                        raise rollback_error from original
                    raise
            try:
                config_attempted = True
                value = ai_config.set_provider(
                    provider_id,
                    url,
                    models,
                    credential=bool(api_key),
                    timeouts=timeouts,
                    filters=filters,
                )
                _restart_llama_swap(active, was_active=service_was_active)
                return value
            except Exception as original:
                try:
                    _rollback_provider_mutation(
                        active=active,
                        provider_id=provider_id,
                        keepass_password=keepass_password,
                        old_config=old_config,
                        old_env=old_env,
                        had_credential=had_credential,
                        old_keepass_key=old_keepass_key,
                        credential_attempted=credential_attempted,
                        config_attempted=config_attempted,
                        service_was_active=service_was_active,
                    )
                except ApiError as rollback_error:
                    raise rollback_error from original
                raise
    except (OperationBusyError, ai_config.AiConfigError, OSError, ApiError) as exc:
        if isinstance(exc, ApiError):
            raise
        raise ApiError(str(exc)) from exc
    finally:
        api_key = ""
        keepass_password = ""
        if old_keepass_key:
            old_keepass_key = ""


def delete_ai_provider(request: dict[str, Any]) -> dict[str, Any]:
    provider_id = _json_string(request, "id", required=True, max_length=48)
    keepass_password = _json_string(request, "keepassPassword", max_length=MAX_PASSWORD_LENGTH)
    old_keepass_key: str | None = None
    try:
        provider_id = ai_config.validate_provider_id(provider_id)
        with acquire_operation("ai-provider-delete", ("secrets", "runtime")) as active:
            old_config = _snapshot_private_file(pathlib.Path(ai_config.CONFIG_PATH), "llama-swap configuration")
            before = ai_config.load_config()
            has_credential = _provider_reference_configured(before, provider_id)
            if has_credential and not keepass_password:
                raise ApiError("KeePassXC database password is required to remove the stored provider credential")
            if "\n" in keepass_password or "\r" in keepass_password:
                raise ApiError("KeePassXC database password must be a single line")
            old_env: PrivateFileSnapshot | None = None
            if has_credential:
                old_env = _snapshot_private_file(_secret_env_path(), "llama-swap runtime secret environment")
                old_keepass_key = _fetch_existing_provider_key(active, provider_id, keepass_password)
            service_was_active = _llama_swap_active(active)
            credential_attempted = False
            config_attempted = False
            try:
                config_attempted = True
                value = ai_config.delete_provider(provider_id)
                if has_credential:
                    credential_attempted = True
                    _write_provider_key(active, provider_id, keepass_password, None)
                _restart_llama_swap(active, was_active=service_was_active)
                return value
            except Exception as original:
                try:
                    _rollback_provider_mutation(
                        active=active,
                        provider_id=provider_id,
                        keepass_password=keepass_password,
                        old_config=old_config,
                        old_env=old_env,
                        had_credential=has_credential,
                        old_keepass_key=old_keepass_key,
                        credential_attempted=credential_attempted,
                        config_attempted=config_attempted,
                        service_was_active=service_was_active,
                    )
                except ApiError as rollback_error:
                    raise rollback_error from original
                raise
    except (OperationBusyError, ai_config.AiConfigError, OSError, ApiError) as exc:
        if isinstance(exc, ApiError):
            raise
        raise ApiError(str(exc)) from exc
    finally:
        keepass_password = ""
        if old_keepass_key:
            old_keepass_key = ""


def set_ai_local_model(request: dict[str, Any]) -> dict[str, Any]:
    model_id = _json_string(request, "id", required=True, max_length=128)
    model_path = _json_string(request, "path", required=True, max_length=4096)
    context = request.get("context")
    ttl = request.get("ttl", -1)
    tools = request.get("tools", False)
    extra_args = request.get("extraArgs", [])
    if isinstance(context, bool) or not isinstance(context, int):
        raise ApiError("Local model context must be an integer")
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        raise ApiError("Local model TTL must be an integer")
    if not isinstance(tools, bool):
        raise ApiError("Local model tools capability must be boolean")
    if not isinstance(extra_args, list) or len(extra_args) > ai_config.MAX_LOCAL_ARGS or any(
        not isinstance(item, str) for item in extra_args
    ):
        raise ApiError("Invalid extraArgs")
    try:
        with operation_guard("ai-local-model-set", ("runtime",)):
            return ai_config.set_local_model(
                model_id,
                model_path,
                context=context,
                ttl=ttl,
                tools=tools,
                extra_args=extra_args,
            )
    except ai_config.AiConfigError as exc:
        raise ApiError(str(exc)) from exc


def delete_ai_local_model(request: dict[str, Any]) -> dict[str, Any]:
    model_id = _json_string(request, "id", required=True, max_length=128)
    try:
        with operation_guard("ai-local-model-delete", ("runtime",)):
            return ai_config.delete_local_model(model_id)
    except ai_config.AiConfigError as exc:
        raise ApiError(str(exc)) from exc


def set_ai_role(request: dict[str, Any]) -> dict[str, Any]:
    role = _json_string(request, "role", required=True, max_length=64)
    targets = _json_string_list(request, "targets", required=True)
    strategy = _json_string(request, "strategy", required=True, max_length=16)
    spillover = request.get("spillover", 1)
    try:
        with operation_guard("ai-role-set", ("runtime",)):
            return ai_config.set_role(role, targets, strategy=strategy, spillover=spillover)
    except ai_config.AiConfigError as exc:
        raise ApiError(str(exc)) from exc


def set_ai_advanced(request: dict[str, Any]) -> dict[str, Any]:
    allowed = {"healthCheckTimeout", "globalTTL", "unloadTimeout", "logLevel", "captureBuffer", "metricsMaxInMemory"}
    values = {key: request[key] for key in allowed if key in request}
    if not values or set(request) - allowed:
        raise ApiError("Advanced AI settings contain unsupported fields")
    try:
        with operation_guard("ai-advanced-set", ("runtime",)):
            return ai_config.replace_advanced(values)
    except ai_config.AiConfigError as exc:
        raise ApiError(str(exc)) from exc


def overview() -> dict[str, Any]:
    features = feature_status()
    feature_rows = features.get("features", []) if isinstance(features.get("features"), list) else []
    units = [
        "nas-protected-services.target",
        "postgresql.service",
        "authentik.service",
        "authentik-worker.service",
        "nas-identity-sync.timer",
        "copyparty.service",
        "cockpit.socket",
        "caddy.service",
        "sanoid.service",
    ]
    if ZFS_REPLICATION_INSTALLED:
        units.append("nas-syncoid.service")
    for feature in feature_rows:
        if not isinstance(feature, dict):
            continue
        for unit in feature.get("units", []):
            if isinstance(unit, dict) and isinstance(unit.get("unit"), str):
                units.append(unit["unit"])
    units = list(dict.fromkeys(units))

    def command_probe(command: list[str]) -> CommandResult:
        return run(command, check=False, timeout_seconds=20)

    probes: dict[str, Any] = {
        "setup": setup_status,
        "identity": identity_status,
        "capabilities": capability_status,
        "update": update_status,
        "aiConfig": ai_configuration,
        "services": lambda: service_states(units),
        "zpool": lambda: command_probe(["zpool", "status", "-x", ZFS_POOL]),
        "zfs": lambda: command_probe(["zfs", "list", "-H", "-o", "name,used,avail,refer,mountpoint", ZFS_DATASET]),
        "failed": lambda: command_probe(["systemctl", "--failed", "--no-legend", "--plain"]),
        "timers": lambda: command_probe(["systemctl", "list-timers", "--all", "--no-legend", "--plain"]),
    }
    results: dict[str, Any] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(probes), thread_name_prefix="nas-overview") as executor:
        futures = {name: executor.submit(probe) for name, probe in probes.items()}
        for name, future in futures.items():
            try:
                results[name] = future.result(timeout=35)
            except concurrent.futures.CancelledError:
                results[name] = {"ok": False, "error": "Probe was cancelled"}
            except Exception as exc:
                reference = secrets.token_hex(6)
                diagnostic(f"nas-cockpit-api overview reference={reference} probe={name} error={exc!r}")
                results[name] = {"ok": False, "error": f"Probe failed (reference {reference})"}

    zpool = results["zpool"]
    zfs = results["zfs"]
    failed = results["failed"]
    timers = results["timers"]
    failed_lines = failed.stdout.strip().splitlines() if isinstance(failed, CommandResult) else []
    timer_lines = timers.stdout.splitlines() if isinstance(timers, CommandResult) else []
    return {
        "host": socket.gethostname(),
        "protectedReady": pathlib.Path("/run/nas-secrets/ready").exists(),
        "zfsReplicationInstalled": ZFS_REPLICATION_INSTALLED,
        "authentikTokenWarning": read_optional_text(pathlib.Path("/run/nas-secrets/authentik-token-warning")),
        "setup": results["setup"],
        "identity": results["identity"],
        "capabilities": results["capabilities"],
        "featureControl": features,
        "update": results["update"],
        "aiConfig": results["aiConfig"],
        "services": results["services"] if isinstance(results["services"], list) else [],
        "zpool": {
            "ok": isinstance(zpool, CommandResult) and zpool.returncode == 0,
            "text": (
                (zpool.stdout or zpool.stderr).strip()
                if isinstance(zpool, CommandResult)
                else str(zpool.get("error", "unavailable"))
            ),
        },
        "zfs": {
            "ok": isinstance(zfs, CommandResult) and zfs.returncode == 0,
            "text": (
                (zfs.stdout or zfs.stderr).strip()
                if isinstance(zfs, CommandResult)
                else str(zfs.get("error", "unavailable"))
            ),
        },
        "failedUnits": failed_lines,
        "timers": [
            line
            for line in timer_lines
            if any(name in line for name in ("nas-", "sanoid", "zfs-scrub", "smart", "restic"))
        ],
        "operationState": operation_state(),
        "links": {
            **endpoint_links(),
            "shares": "/shares/",
            "copypartyConfig": "/shares/admin/copyparty-config/",
            "settings": "/settings/",
            "documentation": "/console/@localhost/nas/docs/index.html",
            "files": "/console/@localhost/files",
            "zfs": "/console/@localhost/zfs",
            "podman": "/console/@localhost/podman",
            "machines": "/console/@localhost/machines",
            "network": "/console/@localhost/network",
            "scheduler": "/console/@localhost/scheduler",
        },
    }


def safe_action(name: str) -> dict[str, Any]:
    spec = ACTIONS.get(name)
    if spec is None:
        raise ApiError(f"Unknown action: {name}")
    if spec.requires_backup and not BACKUP_INSTALLED:
        raise ApiError("Backup support is not installed in this NixOS generation.")
    if spec.requires_replication and not ZFS_REPLICATION_INSTALLED:
        raise ApiError("ZFS replication is not installed in this NixOS generation.")
    if spec.requires_syncthing and not SYNCTHING_INSTALLED:
        raise ApiError("Syncthing support is not installed in this NixOS generation.")

    outputs: list[str] = []
    guard = contextlib.nullcontext() if spec.worker_owns_operation else operation_guard(name, spec.conflicts)
    with guard:
        for command in spec.commands:
            proc = run(command, check=False, timeout_seconds=spec.timeout_seconds)
            if proc.returncode != 0:
                raise operation_error(command, proc)
            if proc.stdout.strip():
                outputs.append(proc.stdout.strip())
    return {"action": name, "ok": True, "output": "\n".join(outputs)}


def set_feature(feature: str, mode: str) -> dict[str, Any]:
    feature = validate_argument(feature, FEATURE_RE, "feature identifier")
    if mode not in {"off", "on-demand", "always"}:
        raise ApiError("Feature mode must be off, on-demand, or always")
    return json_command(["nas-feature-control", "set", feature, mode])


def read_secret_line() -> str:
    line = sys.stdin.readline(MAX_PASSWORD_LENGTH + 2)
    if not line:
        raise ApiError("A KeePassXC database password is required")
    if len(line) > MAX_PASSWORD_LENGTH + 1 or not line.endswith("\n"):
        raise ApiError("KeePassXC database password input is invalid")
    password = line[:-1]
    if not password or "\x00" in password or "\r" in password:
        raise ApiError("KeePassXC database password input is invalid")
    if sys.stdin.read(1):
        raise ApiError("Unexpected data after KeePassXC database password")
    return password


def write_private_file(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def start_first_start_unit(command: list[str], password: str) -> dict[str, Any]:
    try:
        digest_index = command.index("--confirm-plan-digest")
        plan_digest = command[digest_index + 1]
        devices = [command[index + 1] for index, value in enumerate(command) if value == "--confirm-storage-device"]
    except (ValueError, IndexError) as exc:
        raise ApiError("First-start launch command is incomplete") from exc
    reservation = reserve_operation("first-start", FIRST_START_CONFLICTS, ttl_seconds=300)
    job_id = secrets.token_hex(12)
    root = pathlib.Path(os.environ.get("NAS_OPERATION_ROOT", "/run/nas-operations"))
    password_path = root / f"first-start-{job_id}.password"
    request_path = root / f"first-start-{job_id}.json"
    request = {
        "schemaVersion": 1,
        "jobId": job_id,
        "reservationToken": reservation.token,
        "config": FIRST_RUN_CONFIG,
        "planDigest": plan_digest,
        "devices": devices,
        "allowDestructiveStorage": "--allow-destructive-storage" in command,
        "confirmPasswordReapply": "--confirm-password-reapply" in command,
    }
    try:
        write_private_file(password_path, password + "\n")
        write_private_file(request_path, json.dumps(request, sort_keys=True) + "\n")
        setup_program = shutil.which("nas-setup") or "nas-setup"
        unit = f"nas-first-start-job-{job_id}.service"
        launch = [
            "systemd-run",
            "--quiet",
            "--collect",
            f"--unit={unit}",
            "--property=Type=exec",
            "--property=TimeoutStartSec=6h",
            "--property=RuntimeMaxSec=6h",
            "--property=Nice=5",
            "--setenv=NAS_SETUP_ALLOW_ROOT=1",
            setup_program,
            "run-first-start-job",
            "--request-file",
            str(request_path),
            "--password-file",
            str(password_path),
        ]
        result = run(launch, check=False, timeout_seconds=30)
        if result.returncode != 0:
            raise operation_error(launch, result)
        return {
            "status": "started",
            "operationId": job_id,
            "unit": unit,
            "reservationExpiresAt": reservation.expires_at,
        }
    except Exception:
        password_path.unlink(missing_ok=True)
        request_path.unlink(missing_ok=True)
        cancel_reservation(reservation.token)
        raise


def run_first_start(
    *,
    plan_digest: str,
    allow_destructive_storage: bool,
    confirm_password_reapply: bool = False,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", plan_digest):
        raise ApiError("First-start plan digest is invalid")
    status = json_command(
        ["nas-setup", "prepare-first-start", "--config", FIRST_RUN_CONFIG],
        optional=False,
    )
    if status.get("status") in {"complete", "complete-unverified"}:
        return status
    if status.get("status") != "ready":
        raise ApiError(str(status.get("message") or "First-start configuration is not ready"))

    current_digest = status.get("planDigest")
    if not isinstance(current_digest, str) or not secrets.compare_digest(current_digest, plan_digest):
        raise ApiError("The confirmed first-start plan is stale; refresh and review the current plan")

    requires_destructive = status.get("requiresDestructiveConfirmation") is True
    if requires_destructive and not allow_destructive_storage:
        raise ApiError("Confirm destructive storage creation before continuing")

    storage = status.get("storage")
    devices = storage.get("devices", []) if isinstance(storage, dict) else []
    if not isinstance(devices, list) or any(not isinstance(device, str) for device in devices):
        raise ApiError("First-start storage device plan is invalid")

    command = [
        "nas-setup",
        "first-run",
        "--config",
        FIRST_RUN_CONFIG,
        "--keepass-password-stdin",
        "--confirm-plan-digest",
        plan_digest,
    ]
    for device in devices:
        command.extend(["--confirm-storage-device", device])
    if allow_destructive_storage:
        command.append("--allow-destructive-storage")
    if confirm_password_reapply:
        command.append("--confirm-password-reapply")

    password = read_secret_line()
    try:
        return start_first_start_unit(command, password)
    finally:
        password = ""


def main() -> None:
    if os.geteuid() != 0:
        print(json.dumps({"error": "nas-cockpit-api requires Cockpit superuser escalation"}), file=sys.stderr)
        raise SystemExit(1)

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("overview")
    sub.add_parser("ai-config")
    sub.add_parser("ai-provider-set")
    sub.add_parser("ai-provider-delete")
    sub.add_parser("ai-local-model-set")
    sub.add_parser("ai-local-model-delete")
    sub.add_parser("ai-role-set")
    sub.add_parser("ai-advanced-set")
    action = sub.add_parser("action")
    action.add_argument("name", choices=sorted(ACTIONS))
    feature = sub.add_parser("feature")
    feature.add_argument("feature")
    feature.add_argument("mode", choices=["off", "on-demand", "always"])
    first = sub.add_parser("first-run")
    first.add_argument("--allow-destructive-storage", action="store_true")
    first.add_argument("--plan-digest", required=True)
    first.add_argument("--confirm-password-reapply", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "overview":
            result = overview()
        elif args.command == "ai-config":
            result = ai_configuration()
        elif args.command == "ai-provider-set":
            result = set_ai_provider(read_json_request())
        elif args.command == "ai-provider-delete":
            result = delete_ai_provider(read_json_request())
        elif args.command == "ai-local-model-set":
            result = set_ai_local_model(read_json_request())
        elif args.command == "ai-local-model-delete":
            result = delete_ai_local_model(read_json_request())
        elif args.command == "ai-role-set":
            result = set_ai_role(read_json_request())
        elif args.command == "ai-advanced-set":
            result = set_ai_advanced(read_json_request())
        elif args.command == "action":
            result = safe_action(args.name)
        elif args.command == "feature":
            result = set_feature(args.feature, args.mode)
        else:
            result = run_first_start(
                plan_digest=args.plan_digest,
                allow_destructive_storage=args.allow_destructive_storage,
                confirm_password_reapply=args.confirm_password_reapply,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
    except ApiError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
