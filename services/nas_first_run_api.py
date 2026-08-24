#!/usr/bin/env python3
"""Authenticated Unix-socket API for the standalone first-run wizard.

Caddy owns the public TLS and Authentik boundary. This process has no network
listener: it accepts only requests from Caddy over a root/caddy Unix socket,
validates the reviewed setup plan and human credentials, and starts the finite
``nas-setup`` job using private files under ``/run``. Secret request bodies are
never logged or persisted outside those one-shot files.
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
import subprocess
import sys
from typing import Any

from nas_operation_lock import OperationBusyError, cancel_reservation, reserve_operation

FIRST_RUN_CONFIG = os.environ.get("NAS_FIRST_RUN_CONFIG", "/etc/nixos/nixos-nas/first-run.json")
SOCKET_PATH = pathlib.Path(os.environ.get("NAS_FIRST_RUN_API_SOCKET", "/run/nas-first-run-api/api.sock"))
JOB_ROOT = pathlib.Path(os.environ.get("NAS_FIRST_RUN_JOB_ROOT", "/run/nas-first-start"))
RESULT_ROOT = pathlib.Path(os.environ.get("NAS_SETUP_JOB_ROOT", "/var/lib/nas-setup/jobs"))
SETUP_STATE_PATH = pathlib.Path(os.environ.get("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json"))
MAX_BODY_BYTES = 64 * 1024
MAX_PASSWORD_LENGTH = 256
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
BOOTSTRAP_IDENTITY = "akadmin"
ADMIN_GROUP = "nas_admin"


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
        value = json.loads(SETUP_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(value, dict) and value.get("status") in {"complete", "complete-unverified"}


def job_status(job_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{24}", job_id):
        raise RequestError(400, "Invalid first-run job identifier")
    path = RESULT_ROOT / f"{job_id}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schemaVersion": 1, "jobId": job_id, "status": "pending"}
    except (OSError, json.JSONDecodeError) as exc:
        raise RequestError(500, "Unable to read first-run job status") from exc
    if not isinstance(value, dict) or value.get("jobId") != job_id:
        raise RequestError(500, "First-run job status is invalid")
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


def _password_score(password: str) -> int:
    """Return libpwquality's 0..100 score without inventing a password algorithm."""
    completed = subprocess.run(
        ["pwscore"],
        input=password + "\n",
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )
    if completed.returncode != 0:
        return 0
    try:
        return max(0, min(100, int(completed.stdout.strip())))
    except ValueError:
        return 0


def _require_password(password: str, label: str) -> None:
    if len(password) < 15 or _password_score(password) < 60:
        raise RequestError(400, f"{label} does not satisfy the configured password policy")


def password_quality(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != {"password"}:
        raise RequestError(400, "Password-quality request contract is invalid")
    password = _single_line(payload.get("password"), "Password")
    try:
        score = _password_score(password)
        return {
            "schemaVersion": 1,
            "accepted": len(password) >= 15 and score >= 60,
            "score": score,
            "minimumLength": 15,
            "minimumScore": 60,
        }
    finally:
        password = ""


def _write_private_new(path: pathlib.Path, value: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _validated_devices(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 64
        or not all(
            isinstance(item, str)
            and item.startswith("/dev/")
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
    linux_password = _single_line(administrator.get("password"), "Linux administrator password")
    keepass_password = _single_line(payload.get("password"), "KeePassXC master password")
    authentik_password = _single_line(
        payload.get("authentikAdministratorPassword"), "Authentik administrator password"
    )
    for label, value in (
        ("Linux administrator password", linux_password),
        ("KeePassXC master password", keepass_password),
        ("Authentik administrator password", authentik_password),
    ):
        _require_password(value, label)

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

    if subprocess.run(["id", "--user", username], capture_output=True, check=False, timeout=5).returncode == 0:
        raise RequestError(409, f"Administrator username already exists locally: {username}")

    job_id = secrets.token_hex(12)
    try:
        reservation = reserve_operation("first-start-v3", FIRST_START_CONFLICTS, ttl_seconds=3600)
    except OperationBusyError as exc:
        raise RequestError(409, str(exc)) from exc

    JOB_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(JOB_ROOT, 0o700)
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
        "administrator": {
            "username": username,
            "name": name,
            "email": email,
            "password": linux_password,
        },
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
            "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes",
            # First-run must create local accounts and operate on the selected
            # block devices. ProtectSystem=full leaves /etc writable while
            # keeping /usr, /boot and /efi read-only; do not hide host devices.
            "--property=ProtectSystem=full",
            "--property=ProtectHome=yes",
            "--property=ReadWritePaths=/var/lib/nas-setup /var/lib/nas-operational /var/lib/nas-bootstrap /var/lib/nas-secrets /run/nas-secrets /run/nas-operations /run/lock /run/nas-first-start",
            "--property=TimeoutStartSec=6h",
            "--",
            "nas-setup",
            "run-first-start-job",
            "--request-file",
            str(request_path),
            "--password-file",
            str(password_path),
        ]
        completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=30)
        if completed.returncode != 0:
            raise RequestError(500, "Unable to start the first-run setup job")
        return {"schemaVersion": 1, "jobId": job_id, "status": "submitted"}
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
        # Never log request bodies or authorization/identity headers.
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
        if self.command == "GET" and path == "/first-start":
            return 200, setup_status()
        job_match = re.fullmatch(r"/first-start/job/([0-9a-f]{24})", path)
        if self.command == "GET" and job_match:
            return 200, job_status(job_match.group(1))
        if self.command == "POST" and path == "/password-quality":
            return 200, password_quality(self._read_json())
        if self.command == "POST" and path == "/first-run":
            return 202, submit_setup(self._read_json())
        if self.command == "POST" and path == "/reboot":
            return 200, request_reboot()
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
            print(f"nas-first-run-api: internal failure: {exc!r}", file=sys.stderr)
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
