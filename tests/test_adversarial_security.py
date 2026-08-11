from __future__ import annotations

import contextlib
import http.client
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
for path in (SERVICES, ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import adversarial_payloads as payloads
import nas_alert_router as alert_router
import nas_cockpit_api as cockpit_api
import nas_common as common
import nas_identity_model as identity_model
import nas_setup_config as setup_config
import nas_syncthing_devices as syncthing_devices
import nas_v2_readiness as readiness
import nas_v2_session as session


class AdversarialInputTests(unittest.TestCase):
    def test_identity_header_rejects_control_character_injection(self) -> None:
        for payload in payloads.CONTROL_PAYLOADS:
            with self.subTest(payload=repr(payload)):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(common.split_groups(payload), set())

    def test_hostile_group_text_never_grants_v2_application_privilege(self) -> None:
        allow = common.application_capability_group("ai-workspace", "access")
        for payload in payloads.ALL_TEXT_PAYLOADS:
            with self.subTest(payload=repr(payload)):
                with contextlib.redirect_stderr(io.StringIO()):
                    groups = common.split_groups(payload)
                self.assertNotIn(common.ADMIN_GROUP, groups)
                self.assertNotIn(allow, groups)
                self.assertFalse(common.application_capability_allowed(groups, "ai-workspace", "access"))

    def test_identifiers_reject_injection_payloads(self) -> None:
        for payload in payloads.ALL_TEXT_PAYLOADS:
            with self.subTest(payload=repr(payload)):
                with self.assertRaises((identity_model.SyncError, syncthing_devices.DeviceError)):
                    identity_model.validate_uid(payload)
                with self.assertRaises(syncthing_devices.DeviceError):
                    syncthing_devices.validate_username(payload)
                with self.assertRaises(cockpit_api.ApiError):
                    cockpit_api.set_managed_service(payload, "always")

    def test_session_instance_ids_reject_hostile_payloads(self) -> None:
        for payload in payloads.ALL_TEXT_PAYLOADS:
            with self.subTest(payload=repr(payload)), self.assertRaises(session.SessionError):
                session.validate_instance_id(payload)

    def test_readiness_http_rejects_credentials_fragments_and_non_http_schemes(self) -> None:
        rejected = (
            "http://user:secret@127.0.0.1:8080/health",
            "http://127.0.0.1:8080/health#secret",
            "file:///etc/shadow",
            "javascript:alert(1)",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(readiness.ReadinessError):
                readiness._probe_http({"type": "http", "url": url})

    def test_setup_username_and_device_paths_fail_closed(self) -> None:
        for payload in payloads.ALL_TEXT_PAYLOADS:
            with self.subTest(payload=repr(payload)):
                with self.assertRaises(setup_config.SetupError):
                    setup_config.normalize_account({"username": payload}, 0)
        for payload in payloads.PATH_PAYLOADS:
            with self.subTest(path=payload):
                with self.assertRaises(setup_config.SetupError):
                    setup_config.normalize_config(
                        {
                            "schemaVersion": 1,
                            "storage": {"createPool": True, "devices": [payload]},
                        }
                    )

    def test_secrets_reject_multiline_and_nul_payloads(self) -> None:
        for payload in payloads.CONTROL_PAYLOADS:
            with self.subTest(payload=repr(payload)):
                with self.assertRaises(setup_config.SetupError):
                    setup_config.normalize_secret_line(payload, "secret")

    def test_static_security_sink_scan_passes(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "security-static-scan.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


class ManagedServicesV2BoundaryTests(unittest.TestCase):
    def test_deleted_request_time_gate_source_is_absent(self) -> None:
        self.assertFalse((SERVICES / "nas_feature_control.py").exists())

    def test_wake_helper_contains_no_identity_or_group_authorization_logic(self) -> None:
        source = (SERVICES / "nas_v2_wake.py").read_text(encoding="utf-8")
        self.assertNotIn("Remote-User", source)
        self.assertNotIn("Remote-Groups", source)
        self.assertNotIn("X-authentik", source)
        self.assertNotIn("capability_allowed", source)

    def test_caddy_owns_request_time_identity_header_sanitization(self) -> None:
        source = (SERVICES / "nas_v2_caddy.py").read_text(encoding="utf-8")
        self.assertIn("Remote-User", source)
        self.assertIn("X-Authentik", source)
        self.assertIn("forward_auth", source)
        self.assertIn("requiredCapability", source)


class AlertRouterProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.state = pathlib.Path(self.tempdir.name) / "state.json"
        self.patches = [
            mock.patch.object(alert_router, "STATE_PATH", self.state),
            mock.patch.object(alert_router, "NTFY_ENABLED", False),
            mock.patch.object(alert_router, "log_event"),
        ]
        for patch in self.patches:
            patch.start()
        self.server = alert_router.ThreadingHTTPServer(("127.0.0.1", 0), alert_router.Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        for patch in reversed(self.patches):
            patch.stop()
        self.tempdir.cleanup()

    def request(self, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), data
        finally:
            connection.close()

    def test_health_and_unknown_routes(self) -> None:
        self.assertEqual(self.request("GET", "/-/healthy")[0], 200)
        self.assertEqual(self.request("GET", "/not-a-route")[0], 404)
        self.assertEqual(self.request("POST", "/not-a-route", b"[]")[0], 404)

    def test_missing_and_invalid_content_length_are_rejected_without_body_processing(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.putrequest("POST", "/api/v2/alerts")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 411)
            self.assertNotIn(b"Traceback", response.read())
        finally:
            connection.close()

        for value in ("not-a-number", "-1"):
            connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
            try:
                connection.putrequest("POST", "/api/v2/alerts")
                connection.putheader("Content-Length", value)
                connection.endheaders()
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                self.assertNotIn(b"Traceback", response.read())
            finally:
                connection.close()

    def test_malformed_and_wrong_shape_json_are_rejected(self) -> None:
        for body in (b"{", b"{}", b'"string"', b"null"):
            with self.subTest(body=body):
                status, headers, response = self.request(
                    "POST",
                    "/api/v2/alerts",
                    body,
                    {"Content-Type": "application/json", "Content-Length": str(len(body))},
                )
                self.assertEqual(status, 400)
                self.assertEqual(headers.get("Content-Type"), "application/json")
                self.assertNotIn(b"Traceback", response)

    def test_oversized_body_is_rejected_before_read(self) -> None:
        with mock.patch.object(alert_router, "MAX_BODY_BYTES", 8):
            status, _headers, _body = self.request(
                "POST",
                "/api/v2/alerts",
                b"[]",
                {"Content-Length": "9"},
            )
        self.assertEqual(status, 413)

    def test_alert_text_is_bounded_and_returned_as_json_data(self) -> None:
        hostile = payloads.XSS_PAYLOADS[0]
        raw = [
            {
                "labels": {"alertname": hostile, "severity": "warning"},
                "annotations": {"description": hostile},
            }
        ]
        encoded = json.dumps(raw).encode()
        status, headers, body = self.request(
            "POST",
            "/api/v2/alerts",
            encoded,
            {"Content-Type": "application/json", "Content-Length": str(len(encoded))},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        status, headers, body = self.request("GET", "/api/v2/alerts")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")
        parsed = json.loads(body)
        self.assertEqual(parsed[0]["labels"]["alertname"], hostile)


if __name__ == "__main__":
    unittest.main()
