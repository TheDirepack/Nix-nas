#!/usr/bin/env python3
"""Authenticated Unix-socket API for the standalone first-run wizard.

Caddy owns public TLS and Authentik authentication. This process has no network
listener and performs no appliance mutation directly: it validates a reviewed
plan and human credentials, writes only one-shot non-secret job/capability files
under /run, and passes human passwords to the hardened first-start worker over
an anonymous pipe.

The bootstrap Authentik database is intentionally replaced during setup. An
already-authenticated submission therefore receives a random per-job capability
for status polling and the final reboot. The capability is kept only in /run,
never appears in a URL, and cannot submit or alter a setup plan.
"""

from __future__ import annotations

import argparse
from collections import deque
import grp
import http.server
import json
import os
import pathlib
import pwd
import re
import select
import secrets
import socketserver
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
from typing import Any

from nas_operation_lock import OperationBusyError, cancel_reservation, reserve_operation

FIRST_RUN_CONFIG = os.environ.get("NAS_FIRST_RUN_CONFIG", "/etc/nixos/nixos-nas/first-run.json")
FIRST_START_JOB = os.environ.get("NAS_FIRST_START_JOB", "nas-first-start-job")
PASSWORD_QUALITY = os.environ.get("NAS_PASSWORD_QUALITY", "nas-password-quality")
SOCKET_PATH = pathlib.Path(os.environ.get("NAS_FIRST_RUN_API_SOCKET", "/run/nas-first-run-api/api.sock"))
JOB_ROOT = pathlib.Path(os.environ.get("NAS_FIRST_RUN_JOB_ROOT", "/run/nas-first-start"))
RESULT_ROOT = pathlib.Path(os.environ.get("NAS_SETUP_JOB_ROOT", "/var/lib/nas-setup/jobs"))
SETUP_STATE_PATH = pathlib.Path(os.environ.get("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json"))
FIRST_START_STATUS_PATH = pathlib.Path(os.environ.get("NAS_FIRST_START_STATUS", "/var/lib/nas-first-start/status.json"))
MAX_BODY_BYTES = 64 * 1024
MAX_PASSWORD_LENGTH = 256
JOB_CAPABILITY_TTL_SECONDS = max(300, int(os.environ.get("NAS_FIRST_RUN_CAPABILITY_TTL_SECONDS", str(8 * 60 * 60))))
JOB_CAPABILITY_CLOCK_SKEW_SECONDS = 60
FIRST_START_SECRET_DELIVERY_TIMEOUT_SECONDS = max(
    1.0, float(os.environ.get("NAS_FIRST_START_SECRET_DELIVERY_TIMEOUT_SECONDS", "5"))
)
BOOTSTRAP_IDENTITY = "akadmin"
ADMIN_GROUP = "nas_admin"
JOB_CAPABILITY_HEADER = "X-NAS-Setup-Job-Token"
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


class RequestError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


_RATE_LIMITS: dict[str, tuple[int, float]] = {
    "status": (120, 60.0),
    "job-status": (180, 60.0),
    "password-quality": (60, 60.0),
    "submit": (6, 600.0),
    "reboot": (6, 300.0),
}
_RATE_EVENTS: dict[str, deque[float]] = {}
_RATE_LOCK = threading.Lock()


def _enforce_rate_limit(name: str) -> None:
    limit, window = _RATE_LIMITS[name]
    now = time.monotonic()
    with _RATE_LOCK:
        events = _RATE_EVENTS.setdefault(name, deque())
        cutoff = now - window
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= limit:
            raise RequestError(429, "Too many setup requests; retry later")
        events.append(now)


def setup_status() -> dict[str, Any]:
    try:
        return _read_root_json(FIRST_START_STATUS_PATH, "Prepared first-start status")
    except FileNotFoundError as exc:
        raise RequestError(503, "Prepared first-start status is unavailable") from exc


def setup_complete() -> bool:
    try:
        value = _read_root_json(SETUP_STATE_PATH, "First-run completion state")
    except (FileNotFoundError, RequestError):
        return False
    return value.get("status") in {"complete", "complete-unverified"}


def _read_root_json(
    path: pathlib.Path,
    label: str,
    *,
    max_bytes: int = 256 * 1024,
    private: bool = False,
) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RequestError(500, f"Unable to open {label} safely") from exc
    try:
        metadata = os.fstat(descriptor)
        forbidden_mode = 0o077 if private else 0o022
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & forbidden_mode
        ):
            raise RequestError(500, f"{label} has unsafe ownership or mode")
        if metadata.st_size > max_bytes:
            raise RequestError(500, f"{label} exceeds its size limit")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RequestError(500, f"{label} contains invalid JSON") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise RequestError(500, f"{label} is not a JSON object")
    return value


def _validate_job_id(job_id: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{24}", job_id):
        raise RequestError(400, "Invalid first-run job identifier")
    return job_id


def job_status(job_id: str) -> dict[str, Any]:
    job_id = _validate_job_id(job_id)
    try:
        value = _read_root_json(RESULT_ROOT / f"{job_id}.json", "First-run job status")
    except FileNotFoundError:
        return {"schemaVersion": 1, "jobId": job_id, "status": "pending"}
    if value.get("jobId") != job_id:
        raise RequestError(500, "First-run job status does not match its identifier")
    return value


def _capability_path(job_id: str) -> pathlib.Path:
    return JOB_ROOT / f"{_validate_job_id(job_id)}.capability.json"


def require_job_capability(job_id: str, presented: Any) -> None:
    job_id = _validate_job_id(job_id)
    if (
        not isinstance(presented, str)
        or not (32 <= len(presented) <= 128)
        or any(character in presented for character in ("\x00", "\n", "\r"))
    ):
        raise RequestError(401, "Valid setup job capability required")
    try:
        value = _read_root_json(
            _capability_path(job_id),
            "Setup job capability",
            max_bytes=2048,
            private=True,
        )
    except FileNotFoundError as exc:
        raise RequestError(401, "Setup job capability is unavailable") from exc
    expected = value.get("token")
    created_at = value.get("createdAt")
    if (
        set(value) != {"schemaVersion", "jobId", "token", "createdAt"}
        or value.get("schemaVersion") != 1
        or value.get("jobId") != job_id
        or not isinstance(expected, str)
        or not isinstance(created_at, int)
        or isinstance(created_at, bool)
    ):
        raise RequestError(403, "Setup job capability is invalid")
    now = int(time.time())
    if created_at > now + JOB_CAPABILITY_CLOCK_SKEW_SECONDS:
        raise RequestError(403, "Setup job capability has an invalid creation time")
    if now - created_at > JOB_CAPABILITY_TTL_SECONDS:
        _capability_path(job_id).unlink(missing_ok=True)
        raise RequestError(401, "Setup job capability has expired")
    if not secrets.compare_digest(expected, presented):
        raise RequestError(403, "Setup job capability is invalid")


def _single_line(value: Any, label: str, *, maximum: int = MAX_PASSWORD_LENGTH) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(character in value for character in ("\x00", "\n", "\r"))
    ):
        raise RequestError(400, f"{label} must be a non-empty single-line string")
    return value


def password_quality(password: str, user_inputs: list[str]) -> dict[str, Any]:
    payload = json.dumps({"password": password, "userInputs": user_inputs}, separators=(",", ":"))
    try:
        completed = subprocess.run(
            [PASSWORD_QUALITY],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
            timeout=6,
        )
    finally:
        payload = ""
    if completed.returncode != 0:
        raise RequestError(500, "Password-quality service failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RequestError(500, "Password-quality service returned invalid JSON") from exc
    required = {
        "schemaVersion",
        "accepted",
        "localAccepted",
        "minimumLength",
        "minimumZxcvbnScore",
        "zxcvbnScore",
        "warning",
        "suggestions",
        "breachStatus",
        "breachCount",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schemaVersion") != 1:
        raise RequestError(500, "Password-quality service returned an invalid contract")
    if value.get("breachStatus") not in {"clean", "breached", "unavailable"}:
        raise RequestError(500, "Password-quality service returned an invalid breach status")
    return value


def _require_password(password: str, label: str, user_inputs: list[str]) -> dict[str, Any]:
    result = password_quality(password, user_inputs)
    if result.get("localAccepted") is not True:
        raise RequestError(400, f"{label} is too easy to guess; choose a stronger password")
    if result.get("breachStatus") == "breached":
        raise RequestError(400, f"{label} appears in the Have I Been Pwned password corpus")
    return result


def _ensure_private_root_directory(path: pathlib.Path) -> None:
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise RequestError(500, "First-run transient directory parent is unavailable") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != 0
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise RequestError(500, "First-run transient directory parent is unsafe")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise RequestError(500, "Unable to create first-run transient directory safely") from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RequestError(500, "Unable to inspect first-run transient directory") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RequestError(500, "First-run transient directory has unsafe ownership or mode")


def _write_private_new(path: pathlib.Path, value: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validated_devices(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 64
        or not all(
            isinstance(item, str)
            and item.startswith("/dev/")
            and len(item) <= 4096
            and all(character not in item for character in ("\x00", "\n", "\r"))
            for item in value
        )
        or len(value) != len(set(value))
    ):
        raise RequestError(400, "Storage device confirmation is invalid")
    return list(value)


def _reap_first_start(process: subprocess.Popen[bytes]) -> None:
    try:
        process.wait()
    except OSError:
        pass


def _stop_first_start_launcher(process: subprocess.Popen[bytes]) -> None:
    try:
        process.terminate()
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    except OSError:
        pass


def _launch_first_start(command: list[str], secret_request: dict[str, Any]) -> None:
    secret_payload = (json.dumps(secret_request, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        if process.stdin is None:
            raise RequestError(500, "Unable to open first-run secret pipe")
        descriptor = process.stdin.fileno()
        os.set_blocking(descriptor, False)
        deadline = time.monotonic() + FIRST_START_SECRET_DELIVERY_TIMEOUT_SECONDS
        offset = 0
        try:
            while offset < len(secret_payload):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                _, writable, _ = select.select([], [descriptor], [], remaining)
                if not writable:
                    raise TimeoutError
                try:
                    written = os.write(descriptor, secret_payload[offset:])
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise BrokenPipeError
                offset += written
            process.stdin.close()
        except BrokenPipeError as exc:
            _stop_first_start_launcher(process)
            raise RequestError(500, "First-run worker refused its secret pipe") from exc
        except TimeoutError as exc:
            _stop_first_start_launcher(process)
            raise RequestError(500, "Timed out delivering secrets to the first-run worker") from exc

        # systemd-run --wait remains attached until the transient service ends.
        # A short poll catches launch failures while a daemon waiter prevents a
        # zombie process after the long-running setup job eventually exits.
        time.sleep(0.05)
        return_code = process.poll()
        if return_code is not None and return_code != 0:
            raise RequestError(500, "Unable to start the first-run setup job")
        if return_code is None:
            threading.Thread(
                target=_reap_first_start,
                args=(process,),
                name="nas-first-start-reaper",
                daemon=True,
            ).start()
    finally:
        secret_payload = b""
        if process is not None and process.stdin is not None and not process.stdin.closed:
            process.stdin.close()


def submit_setup(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "password",
        "authentikAdministratorPassword",
        "administrator",
        "planDigest",
        "devices",
        "allowDestructiveStorage",
        "confirmPasswordReapply",
    }
    if set(payload) != allowed:
        raise RequestError(400, "First-run request contract is invalid")

    prepared = setup_status()
    if prepared.get("status") in {"complete", "complete-unverified"}:
        return prepared
    if prepared.get("status") != "ready":
        raise RequestError(409, str(prepared.get("message") or "First-run configuration is not ready"))

    plan_digest = _single_line(payload.get("planDigest"), "Plan digest", maximum=64)
    if not re.fullmatch(r"[0-9a-f]{64}", plan_digest):
        raise RequestError(400, "Invalid first-run plan digest")
    current_digest = prepared.get("planDigest")
    if not isinstance(current_digest, str) or not secrets.compare_digest(current_digest, plan_digest):
        raise RequestError(409, "The reviewed first-run plan is stale; reload and review the current plan")

    administrator = payload.get("administrator")
    if not isinstance(administrator, dict) or set(administrator) != {"username", "name", "email", "password"}:
        raise RequestError(400, "Linux administrator details are invalid")
    username = _single_line(administrator.get("username"), "Administrator username", maximum=32)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) or username == "nas-bootstrap":
        raise RequestError(400, "Administrator username is invalid or reserved")
    name = _single_line(administrator.get("name"), "Administrator name", maximum=256)
    email = _single_line(administrator.get("email"), "Administrator email", maximum=320)
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise RequestError(400, "Administrator email is invalid")

    linux_password = _single_line(administrator.get("password"), "Linux administrator password")
    keepass_password = _single_line(payload.get("password"), "KeePassXC master password")
    authentik_password = _single_line(payload.get("authentikAdministratorPassword"), "Authentik administrator password")
    context = [username, name, email]
    breach_checks = {
        "linux": _require_password(linux_password, "Linux administrator password", context),
        "keepass": _require_password(keepass_password, "KeePassXC master password", context),
        "authentik": _require_password(authentik_password, "Authentik administrator password", context),
    }

    devices = _validated_devices(payload.get("devices"))
    storage = prepared.get("storage")
    planned_devices = storage.get("devices", []) if isinstance(storage, dict) else []
    if not isinstance(planned_devices, list) or sorted(devices) != sorted(planned_devices):
        raise RequestError(409, "Confirmed storage devices do not match the reviewed plan")
    allow_destructive = payload.get("allowDestructiveStorage")
    confirm_password_reapply = payload.get("confirmPasswordReapply")
    if not isinstance(allow_destructive, bool) or not isinstance(confirm_password_reapply, bool):
        raise RequestError(400, "First-run confirmations must be boolean")
    if prepared.get("requiresDestructiveConfirmation") is True and not allow_destructive:
        raise RequestError(409, "Confirm destructive storage creation before continuing")

    _ensure_private_root_directory(JOB_ROOT)
    job_id = secrets.token_hex(12)
    job_token = secrets.token_urlsafe(48)
    try:
        reservation = reserve_operation("first-start-v3", FIRST_START_CONFLICTS, ttl_seconds=3600)
    except OperationBusyError as exc:
        raise RequestError(409, str(exc)) from exc

    request_path = JOB_ROOT / f"{job_id}.json"
    capability_path = _capability_path(job_id)
    request = {
        "schemaVersion": 1,
        "jobId": job_id,
        "reservationToken": reservation.token,
        "config": str(pathlib.Path(FIRST_RUN_CONFIG).resolve()),
        "planDigest": plan_digest,
        "devices": devices,
        "allowDestructiveStorage": allow_destructive,
        "confirmPasswordReapply": confirm_password_reapply,
    }
    secret_request = {
        "keepass": keepass_password,
        "administrator": {"username": username, "name": name, "email": email, "password": linux_password},
        "authentikAdministratorPassword": authentik_password,
    }
    try:
        _write_private_new(request_path, request)
        _write_private_new(
            capability_path,
            {"schemaVersion": 1, "jobId": job_id, "token": job_token, "createdAt": int(time.time())},
        )
        # Do not add PrivateTmp, ProtectSystem, ProtectHome, or path-level
        # filesystem sandboxing here. Those options create a mount namespace,
        # but first-start creates and mounts the appliance ZFS dataset and the
        # mount must become host-visible. The job is already a root-only,
        # capability-gated, finite transaction with a restrictive umask.
        command = [
            "systemd-run",
            "--unit",
            f"nas-first-start-{job_id}.service",
            "--collect",
            "--pipe",
            "--wait",
            "--quiet",
            "--property=Type=exec",
            "--property=User=root",
            "--property=Group=root",
            "--property=UMask=0077",
            "--property=NoNewPrivileges=no",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
            "--property=TimeoutStartSec=6h",
            "--setenv=NAS_SETUP_ALLOW_ROOT=1",
            "--",
            FIRST_START_JOB,
            "--request-file",
            str(request_path),
        ]
        _launch_first_start(command, secret_request)
        unavailable = sorted(
            name for name, result in breach_checks.items() if result.get("breachStatus") == "unavailable"
        )
        return {
            "schemaVersion": 1,
            "jobId": job_id,
            "jobToken": job_token,
            "status": "submitted",
            "breachCheckUnavailable": unavailable,
        }
    except Exception:
        request_path.unlink(missing_ok=True)
        capability_path.unlink(missing_ok=True)
        cancel_reservation(reservation.token)
        raise
    finally:
        linux_password = ""
        keepass_password = ""
        authentik_password = ""
        job_token = ""
        secret_request.clear()
        context.clear()


def request_reboot(job_id: str, job_token: str) -> dict[str, Any]:
    require_job_capability(job_id, job_token)
    status = job_status(job_id)
    if status.get("status") != "complete" or not setup_complete():
        raise RequestError(409, "Reboot is only available after this first-run setup job completes")
    completed = subprocess.run(["systemctl", "reboot"], text=True, capture_output=True, check=False, timeout=30)
    if completed.returncode != 0:
        raise RequestError(500, "Unable to schedule reboot")
    _capability_path(job_id).unlink(missing_ok=True)
    return {"schemaVersion": 1, "rebooting": True}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nas-first-run-api"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        print(f"nas-first-run-api: {format % args}", file=sys.stderr)

    def _identity(self) -> str:
        return self.headers.get("Remote-User", "").strip()

    def _groups(self) -> set[str]:
        raw = self.headers.get("Remote-Groups", "")
        return {value.strip() for value in re.split(r"[|,]", raw) if value.strip()}

    def _require_authorized_identity(self) -> None:
        identity = self._identity()
        if not identity:
            raise RequestError(401, "Authenticated bootstrap identity required")
        if identity != BOOTSTRAP_IDENTITY and ADMIN_GROUP not in self._groups():
            raise RequestError(403, "First-run setup requires bootstrap or NAS administrator authority")

    def _require_same_origin(self) -> None:
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site and fetch_site != "same-origin":
            raise RequestError(403, "Cross-site setup mutation refused")
        origin = self.headers.get("Origin", "")
        host = self.headers.get("Host", "")
        try:
            parsed = urllib.parse.urlsplit(origin)
        except ValueError as exc:
            raise RequestError(403, "Invalid setup request origin") from exc
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.netloc != host
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise RequestError(403, "Setup mutation requires the appliance HTTPS origin")

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get_content_type() != "application/json":
            raise RequestError(415, "Setup API accepts application/json only")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise RequestError(400, "Invalid Content-Length") from exc
        if length <= 0 or length > MAX_BODY_BYTES:
            raise RequestError(413, "Setup request body has an invalid size")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RequestError(400, "Invalid JSON request") from exc
        if not isinstance(value, dict):
            raise RequestError(400, "JSON request must be an object")
        return value

    def _send(self, status: int, value: dict[str, Any]) -> None:
        body = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self) -> tuple[int, dict[str, Any]]:
        path = self.path.split("?", 1)[0]

        if self.command == "GET" and (path.startswith("/jobs/") or path.startswith("/first-start/job/")):
            job_id = path.rsplit("/", 1)[-1]
            _validate_job_id(job_id)
            _enforce_rate_limit("job-status")
            require_job_capability(job_id, self.headers.get(JOB_CAPABILITY_HEADER))
            return 200, job_status(job_id)

        if self.command == "POST" and path == "/reboot":
            _enforce_rate_limit("reboot")
            self._require_same_origin()
            request = self._read_json()
            if set(request) != {"jobId"}:
                raise RequestError(400, "Reboot request contract is invalid")
            job_id = _single_line(request.get("jobId"), "Job identifier", maximum=24)
            return 202, request_reboot(job_id, self.headers.get(JOB_CAPABILITY_HEADER, ""))

        self._require_authorized_identity()
        if self.command == "GET" and path in {"/status", "/first-start"}:
            _enforce_rate_limit("status")
            return 200, setup_status()
        if self.command == "POST":
            self._require_same_origin()
        if self.command == "POST" and path == "/password-quality":
            _enforce_rate_limit("password-quality")
            request = self._read_json()
            if set(request) != {"password", "userInputs"}:
                raise RequestError(400, "Password-quality request contract is invalid")
            password = _single_line(request.get("password"), "Password")
            inputs = request.get("userInputs")
            if not isinstance(inputs, list) or len(inputs) > 16 or not all(isinstance(value, str) for value in inputs):
                raise RequestError(400, "Password-quality context is invalid")
            try:
                return 200, password_quality(password, inputs)
            finally:
                password = ""
                inputs.clear()
        if self.command == "POST" and path in {"/apply", "/first-run"}:
            _enforce_rate_limit("submit")
            return 202, submit_setup(self._read_json())
        raise RequestError(404, "Unknown setup API endpoint")

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def _handle(self) -> None:
        try:
            status, value = self._dispatch()
        except RequestError as exc:
            status, value = exc.status, {"error": str(exc)}
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            print(f"nas-first-run-api: internal failure: {type(exc).__name__}", file=sys.stderr)
            status, value = 500, {"error": "First-run setup operation failed"}
        self._send(status, value)


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(socket_path: pathlib.Path) -> None:
    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    socket_path.unlink(missing_ok=True)
    with UnixServer(str(socket_path), Handler) as server:
        try:
            caddy_uid = pwd.getpwnam("caddy").pw_uid
            caddy_gid = grp.getgrnam("caddy").gr_gid
        except KeyError as exc:
            raise RuntimeError("Required caddy principal is unavailable") from exc
        os.chown(socket_path, caddy_uid, caddy_gid)
        os.chmod(socket_path, 0o600)
        server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=pathlib.Path, default=SOCKET_PATH)
    args = parser.parse_args()
    serve(args.socket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
