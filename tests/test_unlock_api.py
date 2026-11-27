"""Browser unlock API (zig/src/unlock_api.zig): authorization, input contract,
throttling, and rollback recovery, exercised over the real Unix socket.

The harness build adds comptime-gated hooks (non-root start, an explicit peer
uid, a short activation timeout, a log file); the production build is checked
to refuse those hooks and to require root.
"""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from zig_binaries import harness_bin_dir, release_bin_dir  # noqa: E402

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
        self.journal = root / "journal.log"
        self.secrets = root / "nas-secrets"
        # The fake accepts only PASSWORD and records argv and stdin separately.
        self.secrets.write_text(
            "#!/bin/sh\n"
            f'echo "nas-secrets $*" >> "{self.calls}"\n'
            f"trap 'echo terminated >> \"{self.calls}\"; exit 143' TERM\n"
            f'IFS= read -r line; printf "%s\\n" "$line" >> "{self.stdin}"\n'
            f'if [ "$line" = "{PASSWORD}" ]; then : > "{self.ready}"; exit 0; fi\n'
            'if [ "$line" = "explode" ]; then echo "Protected service target failed to start" >&2; exit 71; fi\n'
            f'if [ "$line" = "half-unlocked" ]; then : > "{self.ready}"; echo "late failure" >&2; exit 74; fi\n'
            'if [ "$line" = "slow" ]; then sleep 30 & wait; exit 0; fi\n'
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

    def journal_lines(self) -> list[str]:
        return self.journal.read_text(encoding="utf-8").splitlines() if self.journal.exists() else []


def start_server(
    fixture: Fixture,
    socket_path: str,
    allowed_uid: int,
    *,
    binary: pathlib.Path | None = None,
    extra: dict[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "NAS_SECRET_READY": str(fixture.ready),
        "NAS_SETUP_STATE": str(fixture.state),
        "NAS_SECRETS_BIN": str(fixture.secrets),
        "NAS_SYSTEMCTL": str(fixture.systemctl),
        "NAS_CADDY_GROUP": "",
        "NAS_UNLOCK_TEST_ALLOW_NONROOT": "1",
        "NAS_UNLOCK_TEST_ALLOWED_UID": str(allowed_uid),
        "NAS_UNLOCK_TEST_LOG": str(fixture.journal),
        **(extra or {}),
    }
    read_fd, write_fd = os.pipe()
    env["NAS_UNLOCK_TEST_READY_FD"] = str(write_fd)
    process = subprocess.Popen(
        [str(binary or harness_bin_dir() / "nas-unlock-api"), "--socket-path", socket_path],
        env=env,
        pass_fds=(write_fd,),
        stdin=subprocess.DEVNULL,
    )
    os.close(write_fd)
    with os.fdopen(read_fd) as ready:
        line = ready.readline()
    if line.strip() != "ready":
        process.kill()
        raise AssertionError(f"nas-unlock-api did not start (exit {process.wait()})")
    return process


class UnlockApiTests(unittest.TestCase):
    extra_env: dict[str, str] = {}

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = Fixture(pathlib.Path(temporary.name))
        self.socket_path = str(self.fixture.root / "unlock.sock")
        self.server = start_server(self.fixture, self.socket_path, os.geteuid(), extra=self.extra_env)

        def stop() -> None:
            self.server.kill()
            self.server.wait()

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
        journal = "\n".join(self.fixture.journal_lines())
        self.assertIn("unlock attempt by Authentik user 'alice'", journal)
        self.assertIn("unlocked by Authentik user 'alice'", journal)
        self.assertNotIn(PASSWORD, journal)

    def test_wrong_password_is_rejected_and_locked_identity_restarted(self) -> None:
        status, body, _ = self.request("POST", "/unlock/api/activate", {"password": "not the password"})
        self.assertEqual(status, 401)
        self.assertIn("not accepted", str(body["error"]))
        self.assertIn(
            "systemctl start authentik-worker.service authentik.service nas-authentik-proxy-outpost.service",
            self.fixture.log(),
        )
        self.assertNotIn("not the password", "\n".join(self.fixture.journal_lines()))

    def test_activation_failure_is_reported_without_details(self) -> None:
        status, body, _ = self.request("POST", "/unlock/api/activate", {"password": "explode"})
        self.assertEqual(status, 500)
        self.assertIn("rolled back", str(body["error"]))
        self.assertIn("status 71", str(body["error"]))
        self.assertNotIn("Protected service target", str(body["error"]))
        self.assertIn(
            "nas-unlock-api: nas-secrets: Protected service target failed to start",
            "\n".join(self.fixture.journal_lines()),
        )

    def test_restore_is_skipped_once_unlocked(self) -> None:
        status, _, _ = self.request("POST", "/unlock/api/activate", {"password": "half-unlocked"})
        self.assertEqual(status, 500)
        self.assertEqual(self.fixture.log(), ["nas-secrets activate-stdin"])

    def test_failures_back_off(self) -> None:
        self.request("POST", "/unlock/api/activate", {"password": "wrong one"})
        status, body, response = self.request("POST", "/unlock/api/activate", {"password": PASSWORD})
        self.assertEqual(status, 429, body)
        self.assertGreater(int(response.getheader("Retry-After") or 0), 0)
        self.assertIn("retry in", str(body["error"]))
        self.assertFalse(self.fixture.ready.exists())
        self.assertEqual(self.fixture.log().count("nas-secrets activate-stdin"), 1)
        _, status_body, _ = self.request("GET", "/unlock/api/status")
        self.assertGreater(int(str(status_body["retryAfterSeconds"])), 0)

    def test_requires_nas_admin_group(self) -> None:
        for groups in ("users", "nas_administrators", "", None):
            with self.subTest(groups=groups):
                status, _, _ = self.request(
                    "POST", "/unlock/api/activate", {"password": PASSWORD}, headers={"Remote-Groups": groups}
                )
                self.assertEqual(status, 403)
        status, _, _ = self.request(
            "POST", "/unlock/api/activate", {"password": PASSWORD}, headers={"Remote-User": None}
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
            ({}, json.dumps({"password": 5}).encode(), 400),
            ({}, json.dumps(["password"]).encode(), 400),
        ]
        for headers, raw, expected in cases:
            with self.subTest(expected=expected, raw=raw[:30]):
                status, _, _ = self.request("POST", "/unlock/api/activate", headers=headers, raw=raw)
                self.assertEqual(status, expected)
        self.assertEqual(self.fixture.log(), [])

    def test_transfer_encoding_and_missing_length_are_refused(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(self.socket_path)
            client.sendall(
                b"POST /unlock/api/activate HTTP/1.1\r\nHost: nas.local:8443\r\nOrigin: https://nas.local:8443\r\n"
                b"Remote-User: alice\r\nRemote-Groups: nas_admin\r\nContent-Type: application/json\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            )
            self.assertIn(b" 400 ", client.recv(4096).split(b"\r\n", 1)[0] + b" ")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(self.socket_path)
            client.sendall(
                b"POST /unlock/api/activate HTTP/1.1\r\nHost: nas.local:8443\r\nOrigin: https://nas.local:8443\r\n"
                b"Remote-User: alice\r\nRemote-Groups: nas_admin\r\nContent-Type: application/json\r\n\r\n"
            )
            self.assertIn(b" 411 ", client.recv(4096).split(b"\r\n", 1)[0] + b" ")
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

    def test_unknown_paths_are_not_found(self) -> None:
        self.assertEqual(self.request("GET", "/unlock/api/other")[0], 404)
        self.assertEqual(self.request("GET", "/unlock/api/status?x=1")[0], 404)
        self.assertEqual(self.request("POST", "/unlock/api/status", {"password": PASSWORD})[0], 404)
        self.assertEqual(self.request("PUT", "/unlock/api/activate", {"password": PASSWORD})[0], 501)

    def test_socket_is_group_restricted(self) -> None:
        self.assertEqual(os.stat(self.socket_path).st_mode & 0o777, 0o660)


class TimeoutTests(UnlockApiTests):
    extra_env = {"NAS_UNLOCK_TEST_ACTIVATION_TIMEOUT_MS": "500"}

    def test_activation_timeout_is_reported_and_child_may_roll_back(self) -> None:
        started = time.monotonic()
        status, body, _ = self.request("POST", "/unlock/api/activate", {"password": "slow"})
        self.assertEqual(status, 504, body)
        self.assertLess(time.monotonic() - started, 20)
        # SIGTERM first, so nas-secrets runs its rollback before any SIGKILL.
        self.assertIn("terminated", self.fixture.log())
        self.assertIn("nas-unlock-api: nas-secrets activate-stdin timed out", self.fixture.journal_lines())
        self.assertIn(
            "systemctl start authentik-worker.service authentik.service nas-authentik-proxy-outpost.service",
            self.fixture.log(),
        )


class PeerTests(unittest.TestCase):
    def test_unlisted_peer_is_disconnected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(pathlib.Path(raw))
            path = str(fixture.root / "unlock.sock")
            server = start_server(fixture, path, os.geteuid() + 1)
            try:
                connection = UnixHTTPConnection(path)
                with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
                    connection.request("GET", "/unlock/api/status")
                    connection.getresponse()
            finally:
                server.kill()
                server.wait()


class CommandLineTests(unittest.TestCase):
    def run_binary(
        self, binary: pathlib.Path, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(binary), *args],
            env={"PATH": os.environ.get("PATH", ""), **(env or {})},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_production_build_requires_root_and_ignores_test_hooks(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("requires an unprivileged test user")
        result = self.run_binary(
            release_bin_dir() / "nas-unlock-api",
            "--socket-path",
            "/run/nas-unlock/unlock.sock",
            env={"NAS_UNLOCK_TEST_ALLOW_NONROOT": "1"},
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("must run as root", result.stderr)

    def test_socket_path_must_be_absolute_without_parent_references(self) -> None:
        for path in ("relative.sock", "/run/../tmp/unlock.sock"):
            with self.subTest(path=path):
                result = self.run_binary(
                    harness_bin_dir() / "nas-unlock-api",
                    "--socket-path",
                    path,
                    env={"NAS_UNLOCK_TEST_ALLOW_NONROOT": "1"},
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("requires an absolute socket path", result.stderr)

    def test_socket_path_is_required(self) -> None:
        result = self.run_binary(harness_bin_dir() / "nas-unlock-api")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
