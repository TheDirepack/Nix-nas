"""Browser unlock API: authorization, input contract, throttling, and rollback recovery."""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_unlock_api as unlock  # noqa: E402

PASSWORD = "correct horse battery staple"
HOST = "nas.local:8443"
ORIGIN = "https://nas.local:8443"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=10)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self._path)


class Fixture:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.ready = root / "ready"
        self.state = root / "state.json"
        self.state.write_text("{}", encoding="utf-8")
        self.calls = root / "calls.log"
        self.stdin = root / "stdin.log"
        self.secrets = root / "nas-secrets"
        # The fake accepts only PASSWORD and records argv and stdin separately.
        self.secrets.write_text(
            "#!/bin/sh\n"
            f'echo "nas-secrets $*" >> "{self.calls}"\n'
            f'IFS= read -r line; printf "%s\\n" "$line" >> "{self.stdin}"\n'
            f'if [ "$line" = "{PASSWORD}" ]; then : > "{self.ready}"; exit 0; fi\n'
            'if [ "$line" = "explode" ]; then echo "Protected service target failed to start" >&2; exit 71; fi\n'
            'echo "Unable to unlock the KeePassXC database." >&2\n'
            "exit 1\n",
            encoding="utf-8",
        )
        self.systemctl = root / "systemctl"
        self.systemctl.write_text(f'#!/bin/sh\necho "systemctl $*" >> "{self.calls}"\n', encoding="utf-8")
        for tool in (self.secrets, self.systemctl):
            tool.chmod(0o755)

    def log(self) -> list[str]:
        return self.calls.read_text(encoding="utf-8").splitlines() if self.calls.exists() else []


class UnlockApiTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = Fixture(pathlib.Path(temporary.name))
        for name, value in (
            ("SECRET_READY", self.fixture.ready),
            ("SETUP_STATE", self.fixture.state),
            ("NAS_SECRETS_BIN", str(self.fixture.secrets)),
            ("SYSTEMCTL_BIN", str(self.fixture.systemctl)),
        ):
            patcher = mock.patch.object(unlock, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        syslog_patch = mock.patch.object(unlock.syslog, "syslog")
        syslog_patch.start()
        self.addCleanup(syslog_patch.stop)
        self.socket_path = str(self.fixture.root / "unlock.sock")
        self.start_server({os.geteuid()})

    def start_server(self, allowed: set[int]) -> None:
        self.server = unlock.bind(pathlib.Path(self.socket_path), allowed)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()

        def stop() -> None:
            self.server.shutdown()
            self.server.server_close()

        self.addCleanup(stop)

    def request(
        self,
        method: str,
        path: str,
        body: object | None = None,
        *,
        headers: dict[str, str | None] | None = None,
        raw: bytes | None = None,
    ) -> tuple[int, dict[str, object], http.client.HTTPResponse]:
        connection = UnixHTTPConnection(self.socket_path)
        default: dict[str, str | None] = {
            "Host": HOST,
            "Origin": ORIGIN,
            "Remote-User": "alice",
            "Remote-Groups": "users|nas_admin",
            "Content-Type": "application/json",
        }
        if headers is not None:
            default.update(headers)
        payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        sent = {key: value for key, value in default.items() if value is not None}
        connection.request(method, path, body=payload, headers=sent)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, json.loads(data or b"{}"), response

    def test_status_reports_locked_state(self) -> None:
        status, body, _ = self.request("GET", "/unlock/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"busy": False, "locked": True, "retryAfterSeconds": 0, "setupComplete": True})

    def test_correct_password_unlocks_and_travels_only_on_stdin(self) -> None:
        status, body, _ = self.request("POST", "/unlock/api/activate", {"password": PASSWORD})
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"locked": False, "unlocked": True})
        self.assertEqual(self.fixture.log(), ["nas-secrets activate-stdin"])
        self.assertEqual(self.fixture.stdin.read_text(encoding="utf-8"), PASSWORD + "\n")
        self.assertTrue(self.fixture.ready.exists())

    def test_wrong_password_is_rejected_and_locked_identity_restarted(self) -> None:
        status, body, _ = self.request("POST", "/unlock/api/activate", {"password": "not the password"})
        self.assertEqual(status, 401)
        self.assertIn("not accepted", str(body["error"]))
        self.assertIn(
            "systemctl start authentik-worker.service authentik.service nas-authentik-proxy-outpost.service",
            self.fixture.log(),
        )

    def test_activation_failure_is_reported_without_details(self) -> None:
        status, body, _ = self.request("POST", "/unlock/api/activate", {"password": "explode"})
        self.assertEqual(status, 500)
        self.assertIn("rolled back", str(body["error"]))
        self.assertNotIn("Protected service target", str(body["error"]))

    def test_failures_back_off(self) -> None:
        self.request("POST", "/unlock/api/activate", {"password": "wrong one"})
        status, body, response = self.request("POST", "/unlock/api/activate", {"password": PASSWORD})
        self.assertEqual(status, 429, body)
        self.assertGreater(int(response.getheader("Retry-After") or 0), 0)
        self.assertFalse(self.fixture.ready.exists())
        self.assertEqual(self.fixture.log().count("nas-secrets activate-stdin"), 1)

    def test_requires_nas_admin_group(self) -> None:
        for groups in ("users", "nas_administrators", "", None):
            with self.subTest(groups=groups):
                status, _, _ = self.request(
                    "POST", "/unlock/api/activate", {"password": PASSWORD}, headers={"Remote-Groups": groups}
                )
                self.assertEqual(status, 403)
        self.assertEqual(self.fixture.log(), [])

    def test_requires_same_origin(self) -> None:
        for origin in (None, "https://evil.example", "http://nas.local:8443", "null"):
            with self.subTest(origin=origin):
                status, _, _ = self.request(
                    "POST", "/unlock/api/activate", {"password": PASSWORD}, headers={"Origin": origin}
                )
                self.assertEqual(status, 403)
        self.assertEqual(self.fixture.log(), [])

    def test_rejects_malformed_requests(self) -> None:
        cases = [
            ({"Content-Type": "application/x-www-form-urlencoded"}, b"password=x", 415),
            ({}, b"{not json", 400),
            ({}, json.dumps({"password": PASSWORD, "extra": 1}).encode(), 400),
            ({}, json.dumps({"password": ""}).encode(), 400),
            ({}, json.dumps({"password": "a\nb"}).encode(), 400),
            ({}, json.dumps({"password": "x" * 5000}).encode(), 400),
        ]
        for headers, raw, expected in cases:
            with self.subTest(expected=expected, raw=raw[:30]):
                status, _, _ = self.request("POST", "/unlock/api/activate", headers=headers, raw=raw)
                self.assertEqual(status, expected)
        self.assertEqual(self.fixture.log(), [])

    def test_oversized_body_is_refused_without_being_read(self) -> None:
        # The server answers before draining the body, so the client may see
        # the 413 or a reset while it is still sending.
        try:
            status, _, _ = self.request("POST", "/unlock/api/activate", raw=b"x" * (unlock.MAX_BODY_BYTES + 1))
        except (BrokenPipeError, ConnectionResetError):
            status = 413
        self.assertEqual(status, 413)
        self.assertEqual(self.fixture.log(), [])

    def test_refuses_before_setup_and_is_idempotent_when_unlocked(self) -> None:
        self.fixture.state.unlink()
        status, _, _ = self.request("POST", "/unlock/api/activate", {"password": PASSWORD})
        self.assertEqual(status, 409)
        self.fixture.state.write_text("{}", encoding="utf-8")
        self.fixture.ready.write_text("", encoding="utf-8")
        status, body, _ = self.request("POST", "/unlock/api/activate", {"password": PASSWORD})
        self.assertEqual((status, body), (200, {"locked": False, "unlocked": True}))
        self.assertEqual(self.fixture.log(), [])

    def test_unknown_paths_are_not_found(self) -> None:
        self.assertEqual(self.request("GET", "/unlock/api/other")[0], 404)
        self.assertEqual(self.request("POST", "/unlock/api/status", {"password": PASSWORD})[0], 404)


class PeerTests(unittest.TestCase):
    def test_unlisted_peer_is_disconnected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "unlock.sock"
            server = unlock.bind(path, {os.geteuid() + 1})
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = UnixHTTPConnection(str(path))
                with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
                    connection.request("GET", "/unlock/api/status")
                    connection.getresponse()
            finally:
                server.shutdown()
                server.server_close()


class ThrottleTests(unittest.TestCase):
    def test_backoff_doubles_and_resets(self) -> None:
        now = [100.0]
        throttle = unlock.UnlockThrottle(clock=lambda: now[0])
        throttle.acquire()
        with self.assertRaises(unlock.UnlockError) as busy:
            throttle.acquire()
        self.assertEqual(busy.exception.status, 409)
        throttle.release(succeeded=False)
        self.assertEqual(throttle.retry_after(), unlock.FAILURE_BACKOFF_BASE_SECONDS)
        now[0] += unlock.FAILURE_BACKOFF_BASE_SECONDS
        throttle.acquire()
        throttle.release(succeeded=False)
        self.assertEqual(throttle.retry_after(), 2 * unlock.FAILURE_BACKOFF_BASE_SECONDS)
        now[0] += 10_000
        for _ in range(20):
            throttle.acquire()
            throttle.release(succeeded=False)
            now[0] += unlock.FAILURE_BACKOFF_MAX_SECONDS
        self.assertLessEqual(throttle.retry_after(), unlock.FAILURE_BACKOFF_MAX_SECONDS)
        throttle.acquire()
        throttle.release(succeeded=True)
        self.assertEqual(throttle.retry_after(), 0)

    def test_group_header_parsing(self) -> None:
        self.assertTrue(unlock.groups_include_admin("users|nas_admin"))
        self.assertTrue(unlock.groups_include_admin("nas_admin, users"))
        self.assertFalse(unlock.groups_include_admin("nas_admins|users"))
        self.assertFalse(unlock.groups_include_admin(""))


if __name__ == "__main__":
    unittest.main()
