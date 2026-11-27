"""Browser unlock API black-box tests against the Go nas-unlock-api binary.

Authorization, the body contract, throttling and rollback recovery are
exercised over the real Unix socket. Unit-level throttle, origin and body
parsing tests live in go/internal/unlockapi.
"""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest

from tests.go_binaries import binary

PASSWORD = "correct horse battery staple"
HOST = "nas.local:8443"
ORIGIN = "https://nas.local:8443"
MAX_BODY_BYTES = 8192


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
            'if [ "$line" = "slow down" ]; then trap \'echo rolled-back >&2; exit 143\' TERM; sleep 30 >/dev/null 2>&1 & wait; fi\n'
            'echo "Unable to unlock the KeePassXC database." >&2\n'
            "exit 1\n",
            encoding="utf-8",
        )
        self.systemctl = root / "systemctl"
        self.systemctl.write_text(f'#!/bin/sh\necho "systemctl $*" >> "{self.calls}"\n', encoding="utf-8")
        for tool in (self.secrets, self.systemctl):
            tool.chmod(0o755)

    def env(self) -> dict[str, str]:
        return {
            **os.environ,
            "NAS_SECRET_READY": str(self.ready),
            "NAS_SETUP_STATE": str(self.state),
            "NAS_SECRETS_BIN": str(self.secrets),
            "NAS_SYSTEMCTL": str(self.systemctl),
            "NAS_CADDY_GROUP": "",
        }

    def log(self) -> list[str]:
        return self.calls.read_text(encoding="utf-8").splitlines() if self.calls.exists() else []


def start_server(
    test: unittest.TestCase, fixture: Fixture, socket_path: pathlib.Path, *, uid: int, extra: list[str] | None = None
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [
            str(binary("nas-unlock-api", blackbox=True)),
            "--socket-path",
            str(socket_path),
            "--test-allow-peer-uid",
            str(uid),
            *(extra or []),
        ],
        env=fixture.env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    def stop() -> None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stderr is not None:
            process.stderr.close()

    test.addCleanup(stop)
    deadline = time.monotonic() + 10
    while not socket_path.exists():
        if process.poll() is not None or time.monotonic() > deadline:
            raise AssertionError("nas-unlock-api did not start")
        time.sleep(0.02)
    return process


class UnlockApiTests(unittest.TestCase):
    extra: list[str] | None = None

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = Fixture(pathlib.Path(temporary.name))
        self.socket_path = self.fixture.root / "unlock.sock"
        self.process = start_server(self, self.fixture, self.socket_path, uid=os.geteuid(), extra=self.extra)

    def request(
        self,
        method: str,
        path: str,
        body: object | None = None,
        *,
        headers: dict[str, str | None] | None = None,
        raw: bytes | None = None,
    ) -> tuple[int, dict[str, object], http.client.HTTPResponse]:
        connection = UnixHTTPConnection(str(self.socket_path))
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
        status, body, response = self.request("GET", "/unlock/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"busy": False, "locked": True, "retryAfterSeconds": 0, "setupComplete": True})
        self.assertEqual(response.getheader("Cache-Control"), "no-store")

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
        self.assertIn("status 71", str(body["error"]))
        self.assertNotIn("Protected service target", str(body["error"]))

    def test_failures_back_off(self) -> None:
        self.request("POST", "/unlock/api/activate", {"password": "wrong one"})
        status, body, response = self.request("POST", "/unlock/api/activate", {"password": PASSWORD})
        self.assertEqual(status, 429, body)
        self.assertGreater(int(response.getheader("Retry-After") or 0), 0)
        self.assertFalse(self.fixture.ready.exists())
        self.assertEqual(self.fixture.log().count("nas-secrets activate-stdin"), 1)
        status, body, _ = self.request("GET", "/unlock/api/status")
        self.assertGreater(int(str(body["retryAfterSeconds"])), 0)

    def test_requires_nas_admin_group(self) -> None:
        for groups in ("users", "nas_administrators", "", None):
            with self.subTest(groups=groups):
                status, _, _ = self.request(
                    "POST", "/unlock/api/activate", {"password": PASSWORD}, headers={"Remote-Groups": groups}
                )
                self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/unlock/api/activate", {"password": PASSWORD}, headers={"Remote-User": ""})
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
            ({}, json.dumps({"password": 7}).encode(), 400),
            ({}, json.dumps(["password"]).encode(), 400),
        ]
        for headers, raw, expected in cases:
            with self.subTest(expected=expected, raw=raw[:30]):
                status, _, _ = self.request("POST", "/unlock/api/activate", headers=headers, raw=raw)
                self.assertEqual(status, expected)
        self.assertEqual(self.fixture.log(), [])

    def test_missing_content_length_and_chunked_bodies_are_refused(self) -> None:
        connection = UnixHTTPConnection(str(self.socket_path))
        connection.putrequest("POST", "/unlock/api/activate", skip_host=True)
        for name, value in (
            ("Host", HOST),
            ("Origin", ORIGIN),
            ("Remote-User", "alice"),
            ("Remote-Groups", "nas_admin"),
            ("Content-Type", "application/json"),
        ):
            connection.putheader(name, value)
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 411)
        connection.close()
        status, _, _ = self.request(
            "POST",
            "/unlock/api/activate",
            headers={"Transfer-Encoding": "chunked"},
            raw=b"",
        )
        self.assertIn(status, (400, 411))
        self.assertEqual(self.fixture.log(), [])

    def test_oversized_body_is_refused_without_being_read(self) -> None:
        # The server answers before draining the body, so the client may see
        # the 413 or a reset while it is still sending.
        try:
            status, _, _ = self.request("POST", "/unlock/api/activate", raw=b"x" * (MAX_BODY_BYTES + 1))
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

    def test_failure_after_unlock_skips_locked_identity_restore(self) -> None:
        self.fixture.ready.write_text("", encoding="utf-8")
        status, _, _ = self.request("POST", "/unlock/api/activate", {"password": "explode"})
        self.assertEqual(status, 200, "an unlocked appliance answers idempotently without activation")
        self.assertEqual(self.fixture.log(), [])

    def test_unknown_paths_are_not_found(self) -> None:
        self.assertEqual(self.request("GET", "/unlock/api/other")[0], 404)
        self.assertEqual(self.request("POST", "/unlock/api/status", {"password": PASSWORD})[0], 404)
        self.assertEqual(self.request("GET", "/unlock/api/activate")[0], 404)

    def test_socket_mode_is_group_shared(self) -> None:
        self.assertEqual(self.socket_path.stat().st_mode & 0o777, 0o660)


class ActivationTimeoutTests(UnlockApiTests):
    extra = ["--test-activation-timeout", "1s"]

    def test_activation_timeout_is_reported_and_rollback_is_signalled(self) -> None:
        started = time.monotonic()
        status, body, _ = self.request("POST", "/unlock/api/activate", {"password": "slow down"})
        self.assertEqual(status, 504, body)
        self.assertLess(time.monotonic() - started, 9, "SIGTERM must reach nas-secrets so it can roll back")
        self.assertIn(
            "systemctl start authentik-worker.service authentik.service nas-authentik-proxy-outpost.service",
            self.fixture.log(),
        )


class PeerTests(unittest.TestCase):
    def test_unlisted_peer_is_disconnected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(pathlib.Path(raw))
            path = fixture.root / "unlock.sock"
            start_server(self, fixture, path, uid=os.geteuid() + 1)
            connection = UnixHTTPConnection(str(path))
            with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
                connection.request("GET", "/unlock/api/status")
                connection.getresponse()


class StartupTests(unittest.TestCase):
    def test_serve_rejects_relative_or_dot_dot_socket_path(self) -> None:
        for path in ("relative.sock", "/run/../tmp/unlock.sock"):
            with self.subTest(path=path):
                result = subprocess.run(
                    [str(binary("nas-unlock-api", blackbox=True)), "--socket-path", path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("absolute socket path", result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "the root check needs an unprivileged caller")
    def test_production_build_requires_root(self) -> None:
        result = subprocess.run(
            [str(binary("nas-unlock-api")), "--socket-path", "/run/nas-unlock/unlock.sock"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("must run as root", result.stderr)

    def test_production_build_has_no_test_flags(self) -> None:
        result = subprocess.run(
            [str(binary("nas-unlock-api")), "--test-allow-peer-uid", "0", "--socket-path", "/x"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("flag provided but not defined", result.stderr)


if __name__ == "__main__":
    unittest.main()
