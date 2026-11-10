"""Setup-application retirement against an Authentik API served under a configured path."""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
TOKEN = "bootstrap-authority"


class FakeAuthentik(http.server.ThreadingHTTPServer):
    """Authentik's application API, reachable only below one path prefix."""

    def __init__(self, prefix: str, *, present: bool = True, delete_status: int = 204) -> None:
        self.prefix = prefix.rstrip("/") + "/api/v3/"
        self.applications = {"nas-setup", "nas-cockpit"} if present else {"nas-cockpit"}
        self.delete_status = delete_status
        self.requests: list[tuple[str, str]] = []
        super().__init__(("127.0.0.1", 0), FakeAuthentikHandler)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class FakeAuthentikHandler(http.server.BaseHTTPRequestHandler):
    server: FakeAuthentik

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        pass

    def _send(self, status: int, body: object | None = None) -> None:
        payload = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _route(self) -> tuple[str, dict[str, list[str]]] | None:
        self.server.requests.append((self.command, self.path))
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._send(403, {"detail": "forbidden"})
            return None
        parsed = urllib.parse.urlsplit(self.path)
        if not parsed.path.startswith(self.server.prefix):
            self._send(404, {"detail": "not found"})
            return None
        return parsed.path[len(self.server.prefix) :], urllib.parse.parse_qs(parsed.query)

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        routed = self._route()
        if routed is None:
            return
        path, query = routed
        if path != "core/applications/":
            self._send(404, {"detail": "not found"})
            return
        visible = set(self.server.applications)
        # Without superuser_full_list Authentik returns only applications the
        # caller passes policy bindings for; the setup app is bound to a group.
        if query.get("superuser_full_list") != ["true"]:
            visible.discard("nas-setup")
        if "slug" in query:
            visible &= set(query["slug"])
        results = [{"pk": slug, "slug": slug, "name": slug} for slug in sorted(visible)]
        self._send(200, {"pagination": {"next": 0}, "results": results})

    def do_DELETE(self) -> None:  # noqa: N802 - http.server naming
        routed = self._route()
        if routed is None:
            return
        path, _query = routed
        slug = path.removeprefix("core/applications/").rstrip("/")
        if not path.startswith("core/applications/") or slug not in self.server.applications:
            self._send(404, {"detail": "not found"})
            return
        if self.server.delete_status < 300:
            self.server.applications.discard(slug)
        self._send(self.server.delete_status)


class SetupApplicationRetirementCommandTests(unittest.TestCase):
    def serve(self, prefix: str, **kwargs: object) -> FakeAuthentik:
        server = FakeAuthentik(prefix, **kwargs)  # type: ignore[arg-type]
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def retire(self, authentik_url: str) -> subprocess.CompletedProcess[str]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        token = root / "bootstrap-token"
        token.write_text(f"{TOKEN}\n", encoding="utf-8")
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(SERVICES),
            "NAS_AUTHENTIK_URL": authentik_url,
            "NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE": str(token),
            "NAS_AUTHENTIK_TOKEN_FILE": str(root / "runtime-token-must-not-be-used"),
            "NAS_IDENTITY_LOCK": str(root / "identity.lock"),
            "NAS_OPERATION_ROOT": str(root / "operations"),
            "NAS_STATE_ALLOW_UNPRIVILEGED": "1",
        }
        return subprocess.run(
            [sys.executable, str(SERVICES / "nas_identity_sync.py"), "retire-setup-application"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_retirement_uses_the_configured_authentik_path(self) -> None:
        server = self.serve("/auth")
        completed = self.retire(f"{server.base}/auth")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), {"absent": True, "removed": True, "slug": "nas-setup"})
        self.assertNotIn("nas-setup", server.applications)
        self.assertIn("nas-cockpit", server.applications)
        self.assertIn(("DELETE", "/auth/api/v3/core/applications/nas-setup/"), server.requests)
        self.assertTrue(server.requests)
        for _method, path in server.requests:
            self.assertTrue(path.startswith("/auth/api/v3/"), path)

    def test_wrong_api_prefix_fails_instead_of_reporting_not_found(self) -> None:
        server = self.serve("/auth")
        completed = self.retire(f"{server.base}/identity")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertIn("nas-setup", server.applications)
        self.assertFalse(any(method == "DELETE" for method, _path in server.requests))

    def test_absence_is_proved_by_the_full_application_list(self) -> None:
        server = self.serve("/auth", present=False)
        completed = self.retire(f"{server.base}/auth")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), {"absent": True, "removed": False, "slug": "nas-setup"})
        self.assertEqual([method for method, _path in server.requests], ["GET"])
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(server.requests[0][1]).query)
        self.assertEqual(query["superuser_full_list"], ["true"])

    def test_rejected_deletion_fails_closed(self) -> None:
        server = self.serve("/auth", delete_status=403)
        completed = self.retire(f"{server.base}/auth")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertIn("nas-setup", server.applications)


if __name__ == "__main__":
    unittest.main()
