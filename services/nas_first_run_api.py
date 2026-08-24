#!/usr/bin/env python3
"""Private HTTP API for the standalone first-run setup wizard.

Caddy is the network/TLS/authentication boundary. This server listens only on a
Unix socket and accepts authenticated, same-origin JSON requests forwarded by
Caddy. It deliberately does not share the Cockpit API surface.
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
import time
from typing import Any

from nas_operation_lock import OperationBusyError, cancel_reservation, reserve_operation

FIRST_RUN_CONFIG = os.environ.get("NAS_FIRST_RUN_CONFIG", "/etc/nixos/nixos-nas/first-run.json")
SOCKET_PATH = pathlib.Path(os.environ.get("NAS_FIRST_RUN_API_SOCKET", "/run/nas-first-run-api/api.sock"))
JOB_ROOT = pathlib.Path(os.environ.get("NAS_FIRST_RUN_JOB_ROOT", "/run/nas-first-start"))
RESULT_ROOT = pathlib.Path(os.environ.get("NAS_SETUP_JOB_ROOT", "/var/lib/nas-setup/jobs"))
MAX_BODY_BYTES = 64 * 1024
MAX_PASSWORD_LENGTH = 4096
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
    if not isinstance(value, str) or not value or len(value) > maximum or any(ch in value for ch in ("\x00", "\n", "\r")):
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


def password_quality(payload: dict[str, Any]) -> dict[str, Any]:
    password = _single_line(payload.get("password"), "Password")
    try:
        score = _password_score(password)
        # libpwquality handles dictionary/similarity/length policy. The browser
        # adds zxcvbn feedback; this server-side check remains authoritative.
        accepted = len(password) >= 15 and score >= 60
        return {
            "schemaVersion": 1,
            "accepted": accepted,
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


def submit_setup(payload: dict[str, Any]) -> dict[str, Any]:
    prepared = setup_status()
    if prepared.get("status") in {"complete", "complete-unverified"}:
        raise RequestError(409, "First-run setup is already complete")
    if prepared.get("status") != "ready":
        raise RequestError(409, str(prepared.get("message") or "First-run configuration is not ready"))

    plan_digest = _single_line(payload.get("planDigest"), "Plan digest", maximum=64)
    if not re.fullmatch(r"[0-9a-f]{64}", plan_digest):
        raise RequestError(400, "Invalid first-run plan digest")
    current_digest = prepared.get("planDigest")
    if not isinstance(current_digest, str) or not secrets.compare_digest(current_digest, plan_digest):
        raise RequestError(409, "The reviewed first-run plan is stale")

    configuration = payload.get("configuration")
    if not isinstance(configuration, dict):
        configuration = {}
    confirmations = payload.get("confirmations")
    if not isinstance(confirmations, dict):
        confirmations = {}
    secrets_payload = payload.get("secrets")
    if not isinstance(secrets_payload, dict):
        raise RequestError(400, "First-run secrets are missing")

    administrator = secrets_payload.get("administrator")
    if not isinstance(administrator, dict):
        raise RequestError(400, "Linux administrator details are missing")
    username = _single_line(administrator.get("username"), "Administrator username", maximum=32)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) or username == "nas-bootstrap":
        raise RequestError(400, "Administrator username is invalid or reserved")
    name = _single_line(administrator.get("name") or username, "Administrator name", maximum=256)
    email = _single_line(administrator.get("email"), "Administrator email", maximum=320)
    linux_password = _single_line(administrator.get("password"), "Linux administrator password")
    keepass_password = _single_line(secrets_payload.get("keepass"), "KeePassXC master password")
    authentik_password = _single_line(
        secrets_payload.get("authentikAdministratorPassword"), "Authentik administrator password"
    )
    for label, value in (
        ("Linux administrator password", linux_password),
        ("KeePassXC master password", keepass_password),
        ("Authentik administrator password", authentik_password),
    ):
        if len(value) < 15 or _password_score(value) < 60:
            raise RequestError(400, f"{label} does not satisfy the configured password policy")

    devices = confirmations.get("storageDevices", [])
    if not isinstance(devices, list) or not all(isinstance(item, str) and item for item in devices):
        raise RequestError(400, "Storage device confirmation is invalid")
    planned = prepared.get("storage", {}).get("devices", []) if isinstance(prepared.get("storage"), dict) else []
    if sorted(devices) != sorted(planned):
        raise RequestError(409, "Confirmed storage devices do not match the reviewed plan")
    allow_destructive = confirmations.get("allowDestructiveStorage", False)
    confirm_password_reapply = confirmations.get("confirmPasswordReapply", False)
    if not isinstance(allow_destructive, bool) or not isinstance(confirm_password_reapply, bool):
        raise RequestError(400, "First-run confirmations must be boolean")

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
            "--property=ProtectHome=yes",
            "--property=ProtectSystem=strict",
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


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nas-first-run-api"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Never log request bodies or authorization/identity headers.
        print(f"nas-first-run-api: {format % args}", file=sys.stderr)

    def _identity(self) -> str:
        # Caddy deletes client-supplied identity headers before forward_auth and
        # writes this one from Authentik. Direct network access is impossible
        # because this service has only a Unix socket.
        return self.headers.get("Remote-User", "").strip()

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
        if not self._identity():
            raise RequestError(401, "Authenticated bootstrap identity required")
        path = self.path.split("?", 1)[0]
        if self.command == "GET" and path == "/status":
            return 200, setup_status()
        if self.command == "GET" and path.startswith("/jobs/"):
            return 200, job_status(path.removeprefix("/jobs/"))
        if self.command == "POST" and path == "/password-quality":
            return 200, password_quality(self._read_json())
        if self.command == "POST" and path == "/apply":
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
