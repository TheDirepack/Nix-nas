"""Authentik-gated browser unlock for a locked appliance.

The locked Caddy configuration routes /unlock/api/* here only after forward
authentication and a `nas_admin` group check. This process runs as root because
`nas-secrets activate-stdin` loads ZFS keys and restarts the protected target;
it accepts nothing but the KeePass password and passes it on stdin.
"""

from __future__ import annotations

import argparse
import contextlib
import grp
import http.server
import json
import os
import pathlib
import pwd
import re
import socket
import socketserver
import struct
import subprocess
import sys
import syslog
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any, cast

MAX_BODY_BYTES = 8192
MAX_PASSWORD_LENGTH = 4096
SOCKET_TIMEOUT_SECONDS = 30
MAX_CONNECTIONS = 8
ACTIVATION_TIMEOUT_SECONDS = 900
FAILURE_BACKOFF_BASE_SECONDS = 5
FAILURE_BACKOFF_MAX_SECONDS = 300
ADMIN_GROUP = "nas_admin"
WRONG_PASSWORD_MARKER = "Unable to unlock the KeePassXC database."
LOCKED_IDENTITY_UNITS = (
    "authentik-worker.service",
    "authentik.service",
    "nas-authentik-proxy-outpost.service",
)


def _environment_path(name: str, default: str) -> pathlib.Path:
    return pathlib.Path(os.environ.get(name, default))


SECRET_READY = _environment_path("NAS_SECRET_READY", "/run/nas-secret-runtime/live/ready")
SETUP_STATE = _environment_path("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json")
NAS_SECRETS_BIN = os.environ.get("NAS_SECRETS_BIN", "nas-secrets")
SYSTEMCTL_BIN = os.environ.get("NAS_SYSTEMCTL", "systemctl")


class UnlockError(Exception):
    def __init__(self, message: str, *, status: int = 400, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def log(message: str) -> None:
    syslog.syslog(syslog.LOG_NOTICE, message)


def is_locked() -> bool:
    return not SECRET_READY.is_file()


def setup_complete() -> bool:
    return SETUP_STATE.is_file()


def groups_include_admin(header: str) -> bool:
    return ADMIN_GROUP in {item.strip() for item in re.split(r"[|,]", header)}


def validate_password(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise UnlockError("Enter the KeePass database password.")
    if len(value) > MAX_PASSWORD_LENGTH:
        raise UnlockError("The KeePass database password is too long.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise UnlockError("The KeePass database password must be a single line without control characters.")
    return value


class UnlockThrottle:
    """Single-flight activation with exponential delay after failed attempts.

    KDBX key derivation already slows each guess; this additionally bounds how
    fast an authenticated session can drive guesses through the root process.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._running = False
        self._failures = 0
        self._not_before = 0.0

    def retry_after(self) -> int:
        with self._lock:
            return max(0, int(self._not_before - self._clock() + 0.999))

    @property
    def busy(self) -> bool:
        with self._lock:
            return self._running

    def acquire(self) -> None:
        with self._lock:
            if self._running:
                raise UnlockError("An unlock attempt is already running.", status=409)
            wait = self._not_before - self._clock()
            if wait > 0:
                seconds = int(wait + 0.999)
                raise UnlockError(
                    f"Too many failed unlock attempts; retry in {seconds} seconds.", status=429, retry_after=seconds
                )
            self._running = True

    def release(self, *, succeeded: bool) -> None:
        with self._lock:
            self._running = False
            if succeeded:
                self._failures = 0
                self._not_before = 0.0
                return
            self._failures += 1
            delay = min(FAILURE_BACKOFF_BASE_SECONDS * 2 ** (self._failures - 1), FAILURE_BACKOFF_MAX_SECONDS)
            self._not_before = self._clock() + delay


def restore_locked_identity() -> None:
    """Restart the pre-unlock Authentik layer after a rolled-back activation.

    Rollback stops nas-protected-services.target, which also stops Authentik
    through PartOf=. Without this the browser unlock path would disappear until
    the next boot.
    """
    if not is_locked():
        return
    subprocess.run(
        [SYSTEMCTL_BIN, "start", *LOCKED_IDENTITY_UNITS],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=180,
    )


def activate(password: str) -> None:
    try:
        completed = subprocess.run(
            [NAS_SECRETS_BIN, "activate-stdin"],
            input=password + "\n",
            text=True,
            capture_output=True,
            check=False,
            timeout=ACTIVATION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        log("nas-unlock-api: nas-secrets activate-stdin timed out")
        raise UnlockError("Unlock timed out; inspect the appliance journal.", status=504) from exc
    if completed.returncode == 0:
        return
    # nas-secrets never prints secret values; keep the tail for the journal only.
    for line in completed.stderr.strip().splitlines()[-20:]:
        log(f"nas-unlock-api: nas-secrets: {line[:500]}")
    if WRONG_PASSWORD_MARKER in completed.stderr:
        raise UnlockError("The KeePass database password was not accepted.", status=401)
    raise UnlockError(
        f"Activation failed (status {completed.returncode}) and was rolled back; the NAS stays locked. "
        "Inspect `journalctl -t nas-unlock-api` or unlock from the recovery console.",
        status=500,
    )


class UnlockServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True

    def __init__(self, socket_path: str, allowed_uids: Iterable[int], throttle: UnlockThrottle) -> None:
        self.allowed_uids = frozenset(allowed_uids)
        self.throttle = throttle
        self._connection_gate = threading.Semaphore(MAX_CONNECTIONS)
        super().__init__(cast(Any, socket_path), UnlockHandler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind resolves the address with getfqdn(), which is
        # a DNS lookup on the socket path.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = 0

    def get_request(self) -> tuple[socket.socket, Any]:
        request, client_address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT_SECONDS)
        return request, client_address

    def _peer_allowed(self, request: socket.socket) -> bool:
        try:
            _pid, uid, _gid = struct.unpack(
                "iii", request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iii"))
            )
        except OSError:
            return False
        return uid in self.allowed_uids

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._peer_allowed(request) or not self._connection_gate.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_gate.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_gate.release()


class UnlockHandler(http.server.BaseHTTPRequestHandler):
    server_version = "nas-unlock-api/1"
    server: UnlockServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - http.server signature
        return

    def _send_json(self, status: int, payload: dict[str, Any], retry_after: int | None = None) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if retry_after:
            self.send_header("Retry-After", str(retry_after))
        try:
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            return

    def _status_document(self) -> dict[str, Any]:
        return {
            "locked": is_locked(),
            "setupComplete": setup_complete(),
            "busy": self.server.throttle.busy,
            "retryAfterSeconds": self.server.throttle.retry_after(),
        }

    def _require_admin(self) -> str:
        users = self.headers.get_all("Remote-User", [])
        groups = self.headers.get_all("Remote-Groups", [])
        if len(users) != 1 or not users[0] or len(groups) != 1 or not groups_include_admin(groups[0]):
            raise UnlockError("Unlocking requires an Authentik nas_admin session.", status=403)
        return users[0]

    def _require_same_origin(self) -> None:
        origins = self.headers.get_all("Origin", [])
        hosts = self.headers.get_all("Host", [])
        if len(origins) != 1 or len(hosts) != 1:
            raise UnlockError("Unlock requests must come from the unlock page.", status=403)
        authority = re.fullmatch(r"([a-z0-9_.-]+|\[[0-9a-f:.]+\])(?::([0-9]+))?", hosts[0].lower())
        if authority is None:
            raise UnlockError("Unlock requests must come from the unlock page.", status=403)
        hostname, port = authority.groups()
        expected = f"https://{hostname}"
        allowed = {expected, f"{expected}:443"} if port in (None, "443") else {f"{expected}:{port}"}
        if origins[0].lower() not in allowed:
            raise UnlockError("Unlock requests must come from the unlock page.", status=403)

    def _read_password(self) -> str:
        if self.headers.get("Transfer-Encoding") is not None:
            raise UnlockError("Transfer-Encoding is not supported.")
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise UnlockError("Unlock requests must be JSON.", status=415)
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].strip().isdigit():
            raise UnlockError("Unlock requests require one Content-Length header.", status=411)
        length = int(lengths[0].strip())
        if length > MAX_BODY_BYTES:
            raise UnlockError("Unlock request is too large.", status=413)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise UnlockError("Unlock request was truncated.")
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UnlockError("Unlock request is not valid JSON.") from exc
        if not isinstance(request, dict) or set(request) != {"password"}:
            raise UnlockError("Unlock request must contain only the password.")
        return validate_password(request["password"])

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.path != "/unlock/api/status":
            self._send_json(404, {"error": "Not found"})
            return
        self._send_json(200, self._status_document())

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        try:
            if self.path != "/unlock/api/activate":
                raise UnlockError("Not found", status=404)
            self._require_same_origin()
            user = self._require_admin()
            password = self._read_password()
            if not setup_complete():
                raise UnlockError("First-start setup is not complete.", status=409)
            if not is_locked():
                self._send_json(200, {"locked": False, "unlocked": True})
                return
            self.server.throttle.acquire()
            succeeded = False
            log(f"nas-unlock-api: unlock attempt by Authentik user {user!r}")
            try:
                activate(password)
                succeeded = True
            finally:
                password = ""
                self.server.throttle.release(succeeded=succeeded)
                if not succeeded:
                    restore_locked_identity()
            log(f"nas-unlock-api: unlocked by Authentik user {user!r}")
            self._send_json(200, {"locked": False, "unlocked": True})
        except UnlockError as exc:
            self._send_json(exc.status, {"error": str(exc)}, exc.retry_after)


def bind(
    socket_path: pathlib.Path, allowed_uids: Iterable[int], throttle: UnlockThrottle | None = None
) -> UnlockServer:
    with contextlib.suppress(FileNotFoundError):
        if socket_path.is_socket():
            socket_path.unlink()
    return UnlockServer(str(socket_path), allowed_uids, throttle or UnlockThrottle())


def caddy_uids() -> set[int]:
    user = os.environ.get("NAS_CADDY_USER", "caddy")
    try:
        return {0, pwd.getpwnam(user).pw_uid}
    except KeyError:
        return {0}


def serve(socket_path: pathlib.Path) -> int:
    if not socket_path.is_absolute() or ".." in socket_path.parts:
        print("nas-unlock-api requires an absolute socket path", file=sys.stderr)
        return 1
    server = bind(socket_path, caddy_uids())
    group = os.environ.get("NAS_CADDY_GROUP")
    if group:
        os.chown(socket_path, 0, grp.getgrnam(group).gr_gid)
    os.chmod(socket_path, 0o660)
    log(f"nas-unlock-api listening on unix:{socket_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nas-unlock-api")
    parser.add_argument("--socket-path", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    syslog.openlog("nas-unlock-api")
    if os.geteuid() != 0:
        print("nas-unlock-api must run as root", file=sys.stderr)
        return 1
    return serve(args.socket_path)


if __name__ == "__main__":
    raise SystemExit(main())
