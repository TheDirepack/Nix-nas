#!/usr/bin/env python3
"""Allow-listed privileged backend for the Cockpit NAS page."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import http.server
import json
import os
import pathlib
import re
import secrets
import socket
import stat

import sys
import syslog
import tempfile
from dataclasses import dataclass
from typing import Any

import nas_ai_config as ai_config
from nas_common import CommandResult, parse_systemd_show, run_command
from nas_operation_lock import (
    OperationBusyError,
    acquire_operation,
    cancel_reservation,
    operation_state as shared_operation_state,
    reserve_operation,
)

ZFS_POOL = os.environ.get("NAS_ZFS_POOL", "tank")
ZFS_DATASET = os.environ.get("NAS_ZFS_DATASET", "tank/nas")
ZFS_ROOT = pathlib.Path(os.environ.get("NAS_ZFS_ROOT", "/tank"))
CONFIG_DIR = pathlib.Path(os.environ.get("NAS_CONFIG_DIR", "/etc/nixos/nixos-nas"))
PORTAL_MODEL = pathlib.Path(os.environ.get("NAS_V2_PORTAL", "/run/nas-control/portal.json"))
FIRST_RUN_CONFIG = os.environ.get("NAS_FIRST_RUN_CONFIG", "/etc/nixos/nixos-nas/first-run.json")
MAX_PASSWORD_LENGTH = 4096
MAX_ARGUMENT_LENGTH = 128
MAX_JSON_INPUT_BYTES = 128 * 1024
MAX_PRIVATE_SNAPSHOT_BYTES = 4 * 1024 * 1024
SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
FIRST_START_CONFLICTS = (
    "appliance",
    "first-start",
    "identity",
    "runtime",
    "secrets",
    "state",
    "storage",
    "update",
)


class ApiError(RuntimeError):
    """Expected appliance operation failure."""


@dataclass(frozen=True)
class ActionSpec:
    commands: tuple[tuple[str, ...], ...]
    timeout_seconds: int = 300
    conflicts: tuple[str, ...] = ("runtime",)
    worker_owns_operation: bool = False


@dataclass(frozen=True)
class PrivateFileSnapshot:
    exists: bool
    content: bytes = b""
    mode: int = 0o600
    uid: int = 0
    gid: int = 0


HOST_ACTIONS: dict[str, ActionSpec] = {
    "protected-restart": ActionSpec(
        (("systemctl", "start", "nas-protected-restart.service"),),
        conflicts=("identity", "runtime"),
    ),
}


def diagnostic(message: str) -> None:
    try:
        syslog.syslog(syslog.LOG_ERR, message[:2000])
    except OSError:
        if os.environ.get("NAS_DIAGNOSTICS_STDERR") == "1":
            print(message[:2000], file=sys.stderr)


def _secret_command(command: list[str] | tuple[str, ...]) -> bool:
    return bool(command) and pathlib.PurePath(str(command[0])).name == "nas-secrets"


def _setup_entry() -> str:
    """Resolve the nas-setup wrapper, not the bare Python entry point.

    The cockpit API PATH also carries the unwrapped console Python
    application, which shadows the appliance wrapper and its required
    environment (ZFS tooling, pool/dataset names, KeePass database path).
    The wrapper exports NAS_SETUP_BIN pointing at the real wrapper.
    """
    return os.environ.get("NAS_SETUP_BIN", "nas-setup")


def operation_error(command: list[str] | tuple[str, ...], result: CommandResult) -> ApiError:
    reference = secrets.token_hex(6)
    detail = (
        "[secret command output redacted]"
        if _secret_command(command)
        else (result.stderr or result.stdout).strip()[:1000]
    )
    diagnostic(
        f"nas-cockpit-api reference={reference} command={list(command)!r} rc={result.returncode} detail={detail!r}"
    )
    return ApiError(f"Operation failed (reference {reference})")


def run(
    command: list[str] | tuple[str, ...],
    *,
    check: bool = True,
    timeout_seconds: int = 120,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    argv = list(command)
    result = run_command(argv, timeout_seconds=timeout_seconds, input_text=input_text, env=env)
    if check and result.returncode != 0:
        raise operation_error(argv, result)
    return result


def _json_command(command: list[str], *, optional: bool = False, timeout_seconds: int = 30) -> dict[str, Any]:
    result = run(command, check=False, timeout_seconds=timeout_seconds)
    if result.returncode != 0:
        error = operation_error(command, result)
        if optional:
            return {"ok": False, "error": str(error)}
        raise error
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        if optional:
            return {"ok": False, "error": f"{' '.join(command)} returned invalid JSON"}
        raise ApiError(f"{' '.join(command)} returned invalid JSON") from exc
    if not isinstance(value, dict):
        if optional:
            return {"ok": False, "error": f"{' '.join(command)} returned invalid data"}
        raise ApiError(f"{' '.join(command)} returned invalid data")
    return value


def _json_input() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_JSON_INPUT_BYTES + 1)
    if len(raw) > MAX_JSON_INPUT_BYTES:
        raise ApiError("JSON request exceeds the input limit")
    try:
        value = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError("Invalid JSON request") from exc
    if not isinstance(value, dict):
        raise ApiError("JSON request must be an object")
    return value


def _json_string(request: dict[str, Any], name: str, *, required: bool = False, max_length: int = 4096) -> str:
    value = request.get(name, "")
    if not isinstance(value, str) or len(value) > max_length or "\x00" in value:
        raise ApiError(f"{name} must be a string no longer than {max_length} characters")
    if required and not value:
        raise ApiError(f"{name} is required")
    return value


def _json_string_list(request: dict[str, Any], name: str, *, required: bool = False) -> list[str]:
    value = request.get(name, [])
    if (
        not isinstance(value, list)
        or len(value) > ai_config.MAX_MODELS
        or not all(
            isinstance(item, str)
            and 0 < len(item) <= max(ai_config.MAX_MODEL_ID, MAX_ARGUMENT_LENGTH)
            and "\x00" not in item
            for item in value
        )
    ):
        raise ApiError(f"{name} must be a bounded list of non-empty strings")
    if required and not value:
        raise ApiError(f"{name} is required")
    return value


def service_states(units: list[str]) -> dict[str, dict[str, Any]]:
    if not units:
        return {}
    result = run(
        [
            "systemctl",
            "show",
            "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MemoryCurrent,Result",
            *units,
        ],
        check=False,
        timeout_seconds=30,
    )
    if result.returncode != 0:
        return {}
    output: dict[str, dict[str, Any]] = {}
    for unit, row in parse_systemd_show(result.stdout).items():
        memory_raw = row.get("MemoryCurrent")
        try:
            memory = int(memory_raw) if memory_raw and memory_raw != "[not set]" else None
        except ValueError:
            memory = None
        output[unit] = {
            "loadState": row.get("LoadState", "unknown"),
            "activeState": row.get("ActiveState", "unknown"),
            "subState": row.get("SubState", "unknown"),
            "unitFileState": row.get("UnitFileState", "unknown"),
            "result": row.get("Result", "unknown"),
            "memoryBytes": memory,
        }
    return output


def managed_services_status() -> dict[str, Any]:
    try:
        result = run(["nas-managed-services-control", "status"], check=False, timeout_seconds=120)
    except OSError as exc:
        return {"ok": False, "error": f"Managed Services V2 status is unavailable: {exc}", "services": []}
    if result.returncode != 0:
        return {
            "ok": False,
            "error": str(operation_error(["nas-managed-services-control", "status"], result)),
            "services": [],
        }
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": "Managed Services V2 status returned invalid JSON", "services": []}
    if not isinstance(value, dict) or not isinstance(value.get("services"), list):
        return {"ok": False, "error": "Managed Services V2 status has no service list", "services": []}
    value["ok"] = value.get("ok", True) is not False
    return value


def portal_entries() -> list[dict[str, Any]]:
    try:
        value = json.loads(PORTAL_MODEL.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(value, dict) or value.get("schemaVersion") != 2 or value.get("source") != "managed-services-v2":
        return []
    entries = value.get("entries")
    if not isinstance(entries, list):
        return []
    output: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url.startswith("/") or url.startswith("//"):
            continue
        if any(ord(character) < 32 or ord(character) == 127 for character in url):
            continue
        output.append(dict(entry))
    return output


def static_links() -> dict[str, str]:
    return {
        "identity": os.environ.get("NAS_IDENTITY_URL", "/identity/if/user/"),
        "scheduler": "/console/system/services#/timers",
        "virtualMachines": "/console/@localhost/machines",
        "containers": "/console/podman",
        "storage": "/console/storage",
        "network": "/console/network",
        "power": "/console/system",
        "logs": "/console/system/logs",
        "softwareUpdates": "/console/system/software",
        "terminal": "/console/system/terminal",
        "docs": "/console/cockpit/@localhost/nas/docs/index.html",
        "accountSettings": "/settings/",
    }


def setup_status() -> dict[str, Any]:
    prepared = _json_command(
        [_setup_entry(), "prepare-first-start", "--config", FIRST_RUN_CONFIG],
        optional=True,
        timeout_seconds=60,
    )
    status = _json_command([_setup_entry(), "status"], optional=True)
    if prepared.get("ok") is False and "firstStart" not in status:
        status["firstStart"] = prepared
    return status


def identity_status() -> dict[str, Any]:
    return _json_command(["nas-identity-sync", "status"], optional=True)


def capability_status() -> dict[str, Any]:
    return _json_command(["nas-identity-sync", "capabilities"], optional=True)


def update_status() -> dict[str, Any]:
    return _json_command(["nas-update", "--status", "--json"], optional=True)


def ai_configuration() -> dict[str, Any]:
    try:
        return ai_config.public_view(ai_config.load_config())
    except (OSError, ai_config.AiConfigError) as exc:
        return {
            "ok": False,
            "error": str(exc),
            "providers": [],
            "localModels": [],
            "codingRoles": {},
            "availableTargets": [],
        }


def operation_state() -> dict[str, Any]:
    try:
        value = shared_operation_state()
    except OSError as exc:
        value = {"busyClasses": [], "active": [], "error": str(exc)}
    busy = set(value.get("busyClasses", []))
    job_rows = managed_job_rows()
    value.update(
        {
            "conflictsByAction": {
                **{name: list(spec.conflicts) for name, spec in HOST_ACTIONS.items()},
                **{str(row["id"]): ["runtime"] for row in job_rows},
            },
            "workerOwnedActions": [name for name, spec in HOST_ACTIONS.items() if spec.worker_owns_operation],
            "managedJobs": [
                {"id": row["id"], "label": row["label"], "description": row.get("description", "")} for row in job_rows
            ],
            "managedServicesConflicts": sorted(busy & {"runtime", "appliance", "first-start"}),
            "firstStartConflicts": list(FIRST_START_CONFLICTS),
        }
    )
    return value


def managed_job_rows() -> list[dict[str, Any]]:
    """Return enabled V2 jobs that Cockpit may launch through their owner unit."""
    status = managed_services_status()
    rows = status.get("services") if isinstance(status, dict) else None
    if not isinstance(rows, list):
        return []
    jobs: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("workloadKind") != "job":
            continue
        if row.get("managed") is not True or row.get("effective") is not True:
            continue
        units = row.get("units")
        if not isinstance(units, list) or not any(
            isinstance(unit, dict) and unit.get("role") == "owner" and isinstance(unit.get("unit"), str)
            for unit in units
        ):
            continue
        jobs.append(row)
    return sorted(jobs, key=lambda row: str(row.get("id", "")))


def first_start_status() -> dict[str, Any]:
    return _json_command(
        [_setup_entry(), "prepare-first-start", "--config", FIRST_RUN_CONFIG],
        optional=True,
        timeout_seconds=60,
    )


def first_start_job_status(job_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{24}", job_id):
        raise ApiError("Invalid first-start job identifier")
    path = pathlib.Path("/var/lib/nas-setup/jobs") / f"{job_id}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schemaVersion": 1, "jobId": job_id, "status": "pending"}
    except (OSError, json.JSONDecodeError) as exc:
        raise ApiError(f"Unable to read first-start job status: {exc}") from exc
    if not isinstance(value, dict) or value.get("jobId") != job_id:
        raise ApiError("First-start job status is invalid")
    return value


def _write_private_new(path: pathlib.Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _start_first_start_unit(
    job_id: str,
    request_path: pathlib.Path,
    password_path: pathlib.Path,
    devices: list[str],
) -> None:
    command = [
        "systemd-run",
        "--unit",
        f"nas-first-start-{job_id}.service",
        "--collect",
        "--property=Type=exec",
        "--property=User=root",
        "--property=Group=root",
        "--property=UMask=0077",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=DevicePolicy=closed",
        "--property=DeviceAllow=/dev/zfs rw",
        *(f"--property=DeviceAllow={device} rw" for device in devices),
        "--property=ProtectHome=yes",
        "--property=ProtectSystem=strict",
        "--property=RuntimeDirectory=nas-secret-runtime",
        "--property=RuntimeDirectoryMode=0700",
        "--property=RuntimeDirectoryPreserve=yes",
        "--property=ReadWritePaths=/etc /var/lib/nas-bootstrap /var/lib/nas-setup /var/lib/nas-first-start /run/nas-secret-runtime /run/nas-operations /run/lock /run/nas-first-start",
        f"--property=ReadWritePaths=-{ZFS_ROOT}",
        # The submitted job is the Cockpit-authorized root setup execution
        # path; without this flag require_setup_operator fails closed for root.
        "--property=Environment=NAS_SETUP_ALLOW_ROOT=1",
        f"--property=Environment=NAS_PUBLIC_HOST={os.environ.get('NAS_PUBLIC_HOST', '')}",
        "--property=Environment=NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE=/run/nas-authentik/api-token",
        "--property=TimeoutStartSec=6h",
        "--",
        _setup_entry(),
        "run-first-start-job",
        "--request-file",
        str(request_path),
        "--password-file",
        str(password_path),
    ]
    result = run(command, check=False, timeout_seconds=30)
    if result.returncode != 0:
        raise operation_error(command, result)


def start_first_start(request: dict[str, Any]) -> dict[str, Any]:
    password = _json_string(request, "password", required=True, max_length=MAX_PASSWORD_LENGTH)
    if "\n" in password or "\r" in password:
        raise ApiError("KeePassXC database password must be a single line")
    administrator = request.get("administrator")
    if not isinstance(administrator, dict) or set(administrator) != {"username", "name", "email", "password"}:
        raise ApiError("First-start administrator details are invalid")
    username = _json_string(administrator, "username", required=True, max_length=64)
    name = _json_string(administrator, "name", required=True, max_length=256)
    email = _json_string(administrator, "email", required=True, max_length=320)
    administrator_password = _json_string(administrator, "password", required=True, max_length=MAX_PASSWORD_LENGTH)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise ApiError("Administrator username is invalid")
    if username == "nas-bootstrap":
        raise ApiError("Administrator username is the reserved bootstrap identity")
    if any("\n" in value or "\r" in value for value in (name, email, administrator_password)):
        raise ApiError("Administrator details must be single-line values")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ApiError("Administrator email is invalid")
    if len(administrator_password) < 12:
        raise ApiError("Administrator password must contain at least 12 characters")
    plan_digest = _json_string(request, "planDigest", required=True, max_length=64)
    if not re.fullmatch(r"[0-9a-f]{64}", plan_digest):
        raise ApiError("Invalid first-start plan digest")
    devices = _json_string_list(request, "devices")
    if len(devices) != len(set(devices)):
        raise ApiError("First-start devices contain duplicates")
    allow_destructive = request.get("allowDestructiveStorage", False)
    confirm_password_reapply = request.get("confirmPasswordReapply", False)
    if not isinstance(allow_destructive, bool) or not isinstance(confirm_password_reapply, bool):
        raise ApiError("First-start confirmation flags must be boolean")

    prepared = first_start_status()
    if prepared.get("status") in {"complete", "complete-unverified"}:
        return prepared
    if prepared.get("status") != "ready":
        raise ApiError(
            str(prepared.get("message") or prepared.get("error") or "First-start configuration is not ready")
        )
    current_digest = prepared.get("planDigest")
    if not isinstance(current_digest, str) or not secrets.compare_digest(current_digest, plan_digest):
        raise ApiError("The confirmed first-start plan is stale; refresh and review the current plan")
    storage = prepared.get("storage")
    planned_devices = storage.get("devices", []) if isinstance(storage, dict) else []
    if not isinstance(planned_devices, list) or any(not isinstance(device, str) for device in planned_devices):
        raise ApiError("First-start storage device plan is invalid")
    if sorted(devices) != sorted(planned_devices):
        raise ApiError("Confirmed first-start storage devices do not match the reviewed plan")
    if prepared.get("requiresDestructiveConfirmation") is True and not allow_destructive:
        raise ApiError("Confirm destructive storage creation before continuing")

    job_id = secrets.token_hex(12)
    try:
        reservation = reserve_operation(
            "first-start-v2",
            FIRST_START_CONFLICTS,
            ttl_seconds=3600,
        )
    except OperationBusyError as exc:
        raise ApiError(str(exc)) from exc
    request_root = pathlib.Path("/run/nas-first-start")
    request_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(request_root, 0o700)
    request_path = request_root / f"{job_id}.json"
    password_path = request_root / f"{job_id}.password"
    job = {
        "schemaVersion": 1,
        "jobId": job_id,
        "reservationToken": reservation.token,
        "config": str(pathlib.Path(FIRST_RUN_CONFIG).resolve()),
        "planDigest": plan_digest,
        "devices": devices,
        "allowDestructiveStorage": allow_destructive,
        "confirmPasswordReapply": confirm_password_reapply,
    }
    try:
        _write_private_new(request_path, json.dumps(job, sort_keys=True) + "\n")
        _write_private_new(
            password_path,
            json.dumps(
                {
                    "keepass": password,
                    "administrator": {
                        "username": username,
                        "name": name,
                        "email": email,
                        "password": administrator_password,
                    },
                }
            )
            + "\n",
        )
        _start_first_start_unit(job_id, request_path, password_path, devices)
        return {"schemaVersion": 1, "jobId": job_id, "status": "submitted"}
    except Exception:
        request_path.unlink(missing_ok=True)
        password_path.unlink(missing_ok=True)
        cancel_reservation(reservation.token)
        raise
    finally:
        password = ""
        administrator_password = ""


def reconcile_first_start(request: dict[str, Any]) -> dict[str, Any]:
    note = _json_string(request, "note", required=True, max_length=2048)
    result = run([_setup_entry(), "reconcile-first-run", "--note", note], check=False, timeout_seconds=60)
    if result.returncode != 0:
        raise operation_error([_setup_entry(), "reconcile-first-run"], result)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ApiError("nas-setup returned invalid recovery JSON") from exc
    return value if isinstance(value, dict) else {"ok": True}


@contextlib.contextmanager
def operation_guard(action: str, conflicts: tuple[str, ...]):
    try:
        with acquire_operation(action, conflicts):
            yield
    except OperationBusyError as exc:
        raise ApiError(str(exc)) from exc


def run_action(name: str) -> dict[str, Any]:
    spec = HOST_ACTIONS.get(name)
    managed_job = False
    if spec is None:
        if not SERVICE_ID_RE.fullmatch(name):
            raise ApiError("Unknown action: invalid V2 job identifier")
        row = next((candidate for candidate in managed_job_rows() if candidate.get("id") == name), None)
        if row is None:
            raise ApiError(f"Unknown action: {name}")
        owner = next(
            (
                unit.get("unit")
                for unit in row.get("units", [])
                if isinstance(unit, dict) and unit.get("role") == "owner" and isinstance(unit.get("unit"), str)
            ),
            None,
        )
        if owner is None:
            raise ApiError(f"V2 job {name} has no compiled owner unit")
        spec = ActionSpec((("systemctl", "start", owner),), timeout_seconds=21600)
        managed_job = True

    outputs: list[dict[str, Any]] = []
    guard = contextlib.nullcontext() if managed_job else operation_guard(name, spec.conflicts)
    with guard:
        for command in spec.commands:
            result = run(command, check=False, timeout_seconds=spec.timeout_seconds)
            outputs.append(
                {
                    "command": list(command),
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            )
            if result.returncode != 0:
                raise operation_error(command, result)
    return {"ok": True, "action": name, "commands": outputs}


def set_managed_service(service_id: str, mode: str) -> dict[str, Any]:
    if not SERVICE_ID_RE.fullmatch(service_id):
        raise ApiError("Invalid Managed Services V2 service identifier")
    if mode not in {"off", "on-demand", "always"}:
        raise ApiError("Invalid service mode")
    try:
        with acquire_operation("managed-service-policy", ("runtime",)) as active:
            env = dict(os.environ)
            env["NAS_OPERATION_COORDINATION_TOKEN"] = active.coordination_token
            command = ["nas-managed-services-control", "set", service_id, mode]
            result = run(command, check=False, timeout_seconds=180, env=env)
    except OperationBusyError as exc:
        raise ApiError(str(exc)) from exc
    if result.returncode != 0:
        raise operation_error(command, result)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ApiError("Managed Services V2 control returned invalid JSON") from exc
    return value if isinstance(value, dict) else {"ok": True}


def _snapshot_private_file(path: pathlib.Path, label: str) -> PrivateFileSnapshot:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return PrivateFileSnapshot(False)
    except OSError as exc:
        raise ApiError(f"Unable to snapshot {label}") from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ApiError(f"Refusing unsafe {label} path")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ApiError(f"Unable to snapshot {label}") from exc
    try:
        current = os.fstat(descriptor)
        if current.st_dev != before.st_dev or current.st_ino != before.st_ino or not stat.S_ISREG(current.st_mode):
            raise ApiError(f"{label} changed while it was being snapshotted")
        if current.st_size > MAX_PRIVATE_SNAPSHOT_BYTES:
            raise ApiError(f"{label} is unexpectedly large")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(MAX_PRIVATE_SNAPSHOT_BYTES + 1)
        if len(content) > MAX_PRIVATE_SNAPSHOT_BYTES:
            raise ApiError(f"{label} is unexpectedly large")
        return PrivateFileSnapshot(True, content, stat.S_IMODE(current.st_mode), current.st_uid, current.st_gid)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _private_file_snapshot(path: pathlib.Path, label: str) -> PrivateFileSnapshot:
    """Compatibility-free internal alias retained only for local call-site clarity."""
    return _snapshot_private_file(path, label)


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
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.rollback.", dir=parent)
    temporary = pathlib.Path(raw)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(snapshot.content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, snapshot.mode)
        if os.geteuid() == 0:
            os.chown(temporary, snapshot.uid, snapshot.gid)
        os.replace(temporary, path)
        replaced = True
        _fsync_parent(path)
    except OSError as exc:
        raise ApiError(f"Unable to restore {label}") from exc
    finally:
        if not replaced:
            temporary.unlink(missing_ok=True)


def _secret_env_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("NAS_SECRET_ROOT", "/run/nas-secrets")) / "ai" / "llama-swap.env"


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
    env = dict(os.environ)
    env["NAS_OPERATION_COORDINATION_TOKEN"] = active.coordination_token
    command = ["nas-secrets", "show-ai-provider-key-stdin", provider_id]
    result = run(command, check=False, timeout_seconds=30, input_text=f"{keepass_password}\n", env=env)
    if result.returncode != 0:
        diagnostic(
            f"nas-cockpit-api unable to snapshot existing provider credential id={provider_id!r} rc={result.returncode}"
        )
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
    command = ["systemctl", "restart", "nas-llama-swap.service"]
    result = run(command, check=False, timeout_seconds=60, env=env)
    if result.returncode != 0:
        raise operation_error(command, result)
    active_result = run(
        ["systemctl", "is-active", "--quiet", "nas-llama-swap.service"],
        check=False,
        timeout_seconds=10,
        env=env,
    )
    if active_result.returncode != 0:
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
            _write_provider_key(active, provider_id, keepass_password, old_keepass_key if had_credential else None)
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
    if any("\n" in value or "\r" in value for value in (keepass_password, api_key)):
        raise ApiError("Provider credentials must be single-line values")

    old_keepass_key: str | None = None
    try:
        with acquire_operation("ai-provider-set", ("secrets", "runtime")) as active:
            old_config = _snapshot_private_file(pathlib.Path(ai_config.CONFIG_PATH), "llama-swap configuration")
            before = ai_config.load_config()
            had_credential = _provider_reference_configured(before, provider_id)
            old_env: PrivateFileSnapshot | None = None
            service_was_active = _llama_swap_active(active)
            credential_attempted = False
            if api_key:
                old_env = _snapshot_private_file(_secret_env_path(), "llama-swap runtime secret environment")
                if had_credential:
                    old_keepass_key = _fetch_existing_provider_key(active, provider_id, keepass_password)
                credential_attempted = True
                try:
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
                            credential_attempted=True,
                            config_attempted=False,
                            service_was_active=False,
                        )
                    except ApiError as rollback_error:
                        raise rollback_error from original
                    raise
            try:
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
                        config_attempted=True,
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
            had_credential = _provider_reference_configured(before, provider_id)
            if had_credential and not keepass_password:
                raise ApiError("KeePassXC database password is required to remove the stored provider credential")
            if "\n" in keepass_password or "\r" in keepass_password:
                raise ApiError("KeePassXC database password must be a single line")
            old_env: PrivateFileSnapshot | None = None
            if had_credential:
                old_env = _snapshot_private_file(_secret_env_path(), "llama-swap runtime secret environment")
                old_keepass_key = _fetch_existing_provider_key(active, provider_id, keepass_password)
            service_was_active = _llama_swap_active(active)
            try:
                value = ai_config.delete_provider(provider_id)
                if had_credential:
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
                        had_credential=had_credential,
                        old_keepass_key=old_keepass_key,
                        credential_attempted=had_credential,
                        config_attempted=True,
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
    if (
        not isinstance(extra_args, list)
        or len(extra_args) > ai_config.MAX_LOCAL_ARGS
        or any(not isinstance(item, str) for item in extra_args)
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
    managed = managed_services_status()
    units = [
        "nas-protected-services.target",
        "postgresql.service",
        "authentik.service",
        "authentik-worker.service",
        "cockpit.socket",
        "caddy.service",
        "sanoid.service",
    ]
    rows = managed.get("services", []) if isinstance(managed.get("services"), list) else []
    for service in rows:
        if not isinstance(service, dict):
            continue
        for unit in service.get("units", []):
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
    return {
        "host": socket.gethostname(),
        "protectedReady": pathlib.Path("/run/nas-secrets/ready").exists(),
        "authentikTokenWarning": read_optional_text(pathlib.Path("/run/nas-secrets/authentik-token-warning")),
        "setup": results["setup"],
        "identity": results["identity"],
        "capabilities": results["capabilities"],
        "managedServices": managed,
        "update": results["update"],
        "aiConfig": results["aiConfig"],
        "operations": operation_state(),
        "services": results["services"],
        "zfs": {
            "healthy": isinstance(zpool, CommandResult) and zpool.returncode == 0,
            "summary": (zpool.stdout or zpool.stderr).strip() if isinstance(zpool, CommandResult) else "unavailable",
            "dataset": (zfs.stdout or zfs.stderr).strip() if isinstance(zfs, CommandResult) else "unavailable",
        },
        "failedUnits": failed.stdout.strip().splitlines() if isinstance(failed, CommandResult) else [],
        "timers": timers.stdout.splitlines()[:80] if isinstance(timers, CommandResult) else [],
        "links": static_links(),
        "managedServiceLinks": portal_entries(),
    }


def read_optional_text(path: pathlib.Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def source_control(request: dict[str, Any]) -> dict[str, Any]:
    operation = _json_string(request, "operation", required=True, max_length=32)
    allowed = {"status", "diff", "log", "pull", "rebuild", "pull-rebuild"}
    if operation not in allowed:
        raise ApiError("Unsupported source-control operation")
    if not CONFIG_DIR.is_dir():
        raise ApiError(f"Configuration directory does not exist: {CONFIG_DIR}")
    if operation in {"status", "diff", "log"}:
        command = {
            "status": ["git", "-C", str(CONFIG_DIR), "status", "--short", "--branch"],
            "diff": ["git", "-C", str(CONFIG_DIR), "diff", "--stat"],
            "log": ["git", "-C", str(CONFIG_DIR), "log", "--oneline", "-20"],
        }[operation]
        result = run(command, check=False, timeout_seconds=60)
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    try:
        with acquire_operation(f"source-{operation}", ("appliance", "update")) as active:
            env = dict(os.environ)
            env["NAS_OPERATION_COORDINATION_TOKEN"] = active.coordination_token
            outputs: list[dict[str, Any]] = []
            if operation in {"pull", "pull-rebuild"}:
                command = ["git", "-C", str(CONFIG_DIR), "pull", "--ff-only"]
                result = run(command, check=False, timeout_seconds=180, env=env)
                outputs.append(
                    {
                        "command": command,
                        "returncode": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }
                )
                if result.returncode != 0:
                    raise operation_error(command, result)
            if operation in {"rebuild", "pull-rebuild"}:
                command = ["nixos-rebuild", "switch", "--flake", f"{CONFIG_DIR}#nas"]
                result = run(command, check=False, timeout_seconds=1800, env=env)
                outputs.append(
                    {
                        "command": command,
                        "returncode": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }
                )
                if result.returncode != 0:
                    raise operation_error(command, result)
            return {"ok": True, "operation": operation, "commands": outputs}
    except OperationBusyError as exc:
        raise ApiError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("overview")
    sub.add_parser("operations")
    sub.add_parser("first-start-status")
    job = sub.add_parser("first-start-job-status")
    job.add_argument("job_id")
    sub.add_parser("first-start")
    sub.add_parser("first-start-reconcile")
    action = sub.add_parser("action")
    action.add_argument("name", help="Host action or enabled Managed Services V2 job identifier")
    managed = sub.add_parser("managed-service")
    managed.add_argument("service")
    managed.add_argument("mode", choices=["off", "on-demand", "always"])
    sub.add_parser("ai-provider-set")
    sub.add_parser("ai-provider-delete")
    sub.add_parser("ai-local-model-set")
    sub.add_parser("ai-local-model-delete")
    sub.add_parser("ai-role-set")
    sub.add_parser("ai-advanced-set")
    sub.add_parser("source-control")
    serve = sub.add_parser("serve", help="Serve the first-start setup API on loopback for the setup wizard")
    serve.add_argument("--bind", default="127.0.0.1", help="Loopback address to bind")
    serve.add_argument("--port", type=int, default=8980, help="Loopback TCP port to bind")
    return parser


SETUP_STATE_PATH = pathlib.Path(os.environ.get("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json"))
SETUP_API_JOB_RE = re.compile(r"^/setup/api/first-start/job/([0-9a-f]{24})$")


def _setup_complete() -> bool:
    try:
        state = json.loads(SETUP_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(state, dict) and state.get("status") in {"complete", "complete-unverified"}


class SetupApiHandler(http.server.BaseHTTPRequestHandler):
    """Loopback-only JSON API for the first-start setup wizard.

    Exposure is gated by Caddy forward-auth; the handlers reuse the exact
    validation and job-submission path as the Cockpit first-start page.
    """

    server_version = "nas-setup-api/1"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _api_error(self, exc: Exception) -> None:
        self._send_json(400, {"error": str(exc)})

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        try:
            if self.path == "/setup/api/first-start":
                self._send_json(200, first_start_status())
                return
            job_match = SETUP_API_JOB_RE.fullmatch(self.path)
            if job_match:
                self._send_json(200, first_start_job_status(job_match.group(1)))
                return
            self._send_json(404, {"error": "Not found"})
        except (ApiError, OSError, ValueError, ai_config.AiConfigError) as exc:
            self._api_error(exc)

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_JSON_INPUT_BYTES:
                raise ApiError("JSON request exceeds the input limit")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                request = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ApiError("Invalid JSON request") from exc
            if not isinstance(request, dict):
                raise ApiError("JSON request must be an object")
            if self.path == "/setup/api/first-run":
                self._send_json(200, start_first_start(request))
                return
            if self.path == "/setup/api/reboot":
                if not _setup_complete():
                    raise ApiError("Reboot is only offered after first-start setup completes")
                completed = run(["systemctl", "reboot"], check=False, timeout_seconds=30)
                if completed.returncode != 0:
                    raise ApiError("Unable to schedule the reboot")
                self._send_json(200, {"rebooting": True})
                return
            self._send_json(404, {"error": "Not found"})
        except (ApiError, OSError, ValueError, ai_config.AiConfigError) as exc:
            self._api_error(exc)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        syslog.syslog(syslog.LOG_INFO, "nas-setup-api %s" % (format % args))


def serve_setup_api(bind: str, port: int) -> int:
    if not re.fullmatch(r"127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|::1", bind):
        print("nas-cockpit-api serve refuses non-loopback bind addresses", file=sys.stderr)
        return 1
    server = http.server.ThreadingHTTPServer((bind, port), SetupApiHandler)
    syslog.syslog(syslog.LOG_INFO, f"nas-setup-api listening on {bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main() -> int:
    if os.geteuid() != 0 and "--help" not in sys.argv and "-h" not in sys.argv:
        print("nas-cockpit-api requires Cockpit superuser escalation", file=sys.stderr)
        return 1
    args = build_parser().parse_args()
    try:
        if args.command == "overview":
            result = overview()
        elif args.command == "operations":
            result = operation_state()
        elif args.command == "first-start-status":
            result = first_start_status()
        elif args.command == "first-start-job-status":
            result = first_start_job_status(args.job_id)
        elif args.command == "first-start":
            result = start_first_start(_json_input())
        elif args.command == "first-start-reconcile":
            result = reconcile_first_start(_json_input())
        elif args.command == "action":
            result = run_action(args.name)
        elif args.command == "managed-service":
            result = set_managed_service(args.service, args.mode)
        elif args.command == "ai-provider-set":
            result = set_ai_provider(_json_input())
        elif args.command == "ai-provider-delete":
            result = delete_ai_provider(_json_input())
        elif args.command == "ai-local-model-set":
            result = set_ai_local_model(_json_input())
        elif args.command == "ai-local-model-delete":
            result = delete_ai_local_model(_json_input())
        elif args.command == "ai-role-set":
            result = set_ai_role(_json_input())
        elif args.command == "ai-advanced-set":
            result = set_ai_advanced(_json_input())
        elif args.command == "source-control":
            result = source_control(_json_input())
        elif args.command == "serve":
            return serve_setup_api(args.bind, args.port)
        else:  # pragma: no cover
            raise ApiError(f"Unsupported command: {args.command}")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ApiError, OSError, ValueError, ai_config.AiConfigError) as exc:
        print(f"nas-cockpit-api: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
