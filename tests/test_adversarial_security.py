from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
for path in (SERVICES, ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import adversarial_payloads as payloads
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
        allow = common.application_capability_group("grafana", "admin")
        for payload in payloads.ALL_TEXT_PAYLOADS:
            with self.subTest(payload=repr(payload)):
                with contextlib.redirect_stderr(io.StringIO()):
                    groups = common.split_groups(payload)
                self.assertNotIn(common.ADMIN_GROUP, groups)
                self.assertNotIn(allow, groups)
                self.assertFalse(common.application_capability_allowed(groups, "grafana", "admin"))

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

    def test_native_activation_contains_no_identity_or_group_authorization_logic(self) -> None:
        self.assertFalse((SERVICES / "nas_v2_wake.py").exists())
        source = (SERVICES / "nas_v2_activation.py").read_text(encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
