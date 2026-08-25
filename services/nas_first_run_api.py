#!/usr/bin/env python3
"""Authenticated Unix-socket API for the standalone first-run wizard.

Caddy owns public TLS and Authentik authentication. This process has no network
listener and performs no appliance mutation directly: it validates a reviewed
plan and human credentials, writes one-shot root-only job files under /run, and
starts the finite hardened first-start job.
"""

from __future__ import annotations

import argparse
import grp
import http.server
import json
import os
import pathlib
import re
import secrets
import socketserver
import stat
import subprocess
import sys
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
MAX_BODY_BYTES = 64 * 1024
MAX_PASSWORD_LENGTH = 256
BOOTSTRAP_IDENTITY = "akadmin"
ADMIN_GROUP = "nas_admin"
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


def _command_json(command: list[str], *, timeout: int = 60) -> dict[str, Any]:
    completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=timeout)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit status {completed.returncode}"
        raise RequestError(500, detail[:1000])
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RequestError(500, "Setup command returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise RequestError(500, "Setup command returned an invalid response")
    return value


def setup_status() -> dict[str, Any]:
    return _command_json(["nas-setup", "prepare-first-start", "--config", FIRST_RUN_CONFIG])


def setup_complete() -> bool:
    try:
        value = _read_root_json(SETUP_STATE_PATH, "First-run completion state")
    except (FileNotFoundError, RequestError):
        return False
    return value.get("status") in {"complete", "complete-unverified"}


def _read_root_json(path: pathlib.Path, label: str, *, max_bytes: int = 256 * 1024) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RequestError(500, f"Unable to open {label} safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
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


def job_status(job_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{24}", job_id):
        raise RequestError(400, "Invalid first-run job identifier")
    try:
        value = _read_root_json(RESULT_ROOT / f"{job_id}.json", "First-run job status")
    except FileNotFoundError:
        return {"schemaVersion": 1, "jobId": job_id, "status": "pending"}
    if value.get("jobId") != job_id:
        raise RequestError(500, "First-run job status does not match its identifier")
    return value


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
    """Create or verify a root-only transient directory without following its final component."""
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
    authentik_password = _single_line(
        payload.get("authentikAdministratorPassword"), "Authentik administrator password"
    )
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
    try:
        reservation = reserve_operation("first-start-v3", FIRST_START_CONFLICTS, ttl_seconds=3600)
    except OperationBusyError as exc:
        raise RequestError(409, str(exc)) from exc

    request_path = JOB_ROOT / f"{job_id}.json"
    password_path = JOB_ROOT / f"{job_id}.password"
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
        _write_private_new(password_path, secret_request)
        command = [
            "systemd-run",
            "--unit",
            f"nas-first-start-{job_id}.service",
            "--collect",
            "--property=Type=exec",
            "--property=User=root",
            "--property=Group=root",
            "--property=UMask=0077",
            # This authenticated finite job deliberately creates accounts,
            # changes /etc, operates block devices, mounts ZFS, and performs
            # controlled uid transitions. The long-running API remains NNP.
            "--property=NoNewPrivileges=no",
            "--property=PrivateTmp=yes",
            "--property=ProtectSystem=full",
            "--property=ProtectHome=read-only",
            "--property=ReadWritePaths=/etc /home /var/lib/nas-setup /var/lib/nas-operational /var/lib/nas-bootstrap /var/lib/nas-secrets /run/nas-secrets /run/nas-operations /run/lock /run/nas-first-start",
            "--property=TimeoutStartSec=6h",
            "--setenv=NAS_SETUP_ALLOW_ROOT=1",
            "--",
            FIRST_START_JOB,
            "--request-file",
            str(request_path),
            "--password-file",
            str(password_path),
        ]
        completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=30)
        if completed.returncode != 0:
            raise RequestError(500, "Unable to start the first-run setup job")
        unavailable = sorted(name for name, result in breach_checks.items() if result.get("breachStatus") == "unavailable")
        return {
            "schemaVersion": 1,
            "jobId": job_id,
            "status": "submitted",
            "breachCheckUnavailable": unavailable,
        }
    except Exception:
        request_path.unlink(missing_ok=True)
        password_path.unlink(missing_ok=True)
        cancel_reservation(reservation.token)
        raise
    finally:
        linux_password = ""
        keepass_password = ""
        authentik_password = ""
        secret_request.clear()
        context.clear()


def request_reboot() -> dict[str, Any]:
    if not setup_complete():
        raise RequestError(409, "Reboot is only available after first-run setup completes")
    completed = subprocess.run(["systemctl", "reboot"], text=True, capture_output=True, check=False, timeout=30)
    if completed.returncode != 0:
        raise RequestError(500, "Unable to schedule reboot")
    return {"schemaVersion": 1, "rebooting": True}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nas-first-run-api"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # BaseHTTPRequestHandler logs only request metadata; never bodies or
        # identity/authorization headers.
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
        if parsed.scheme != "https" or not parsed.netloc or parsed.netloc != host or parsed.path or parsed.query or parsed.fragment:
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
        self._require_authorized_identity()
        path = self.path.split("?", 1)[0]
        if self.command == "GET" and path in {"/status", "/first-start"}:
            return 200, setup_status()
        if self.command == "GET" and (path.startswith("/jobs/") or path.startswith("/first-start/job/")):
            job_id = path.rsplit("/", 1)[-1]
            return 200, job_status(job_id)
        if self.command == "POST":
            self._require_same_origin()
        if self.command == "POST" and path == "/password-quality":
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
            return 202, submit_setup(self._read_json())
        if self.command == "POST" and path == "/reboot":
            return 202, request_reboot()
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
        os.chmod(socket_path, 0o660)
        try:
            os.chown(socket_path, 0, grp.getgrnam("caddy").gr_gid)
        except KeyError:
            pass
        server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=pathlib.Path, default=SOCKET_PATH)
    args = parser.parse_args()
    serve(args.socket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
