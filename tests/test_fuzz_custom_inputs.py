"""Generated rejection and invariant checks for custom pure input boundaries."""

from __future__ import annotations

import copy
import contextlib
import io
import pathlib
import sys
import unittest
from hypothesis import given, settings, strategies as st

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_common as common  # noqa: E402
import nas_logging  # noqa: E402
import nas_setup_config as setup_config  # noqa: E402
import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_spec as v2_spec  # noqa: E402
import nas_v2_activation as activation  # noqa: E402
import nas_syncthing_devices as syncthing  # noqa: E402


BASE_V2_DOCUMENT = {
    "schemaVersion": 3,
    "services": {
        "demo": {
            "name": "Demo",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "systemd", "unit": "demo.service"},
        }
    },
}
TEXT = st.text(max_size=512)
INVALID_TEXT = st.tuples(TEXT, st.sampled_from(["\x00", "\r", "\n"]), TEXT).map(
    lambda parts: "a" + "".join(parts) + "b"
)
INVALID_UNIT = INVALID_TEXT | st.sampled_from(["", "../demo.service", "demo"])
INVALID_ID = INVALID_TEXT | st.sampled_from(["", "A", "../escape", "a" * 65])


class CustomInputSurfaceFuzzTests(unittest.TestCase):
    @settings(max_examples=200, deadline=None)
    @given(INVALID_UNIT)
    def test_v2_document_compilation_rejects_hostile_service_fields(self, value: str) -> None:
        document = copy.deepcopy(BASE_V2_DOCUMENT)
        document["services"]["demo"]["runtime"]["unit"] = value
        before = copy.deepcopy(document)
        with self.assertRaises(v2_spec.ManagedServicesV2Error):
            v2_spec.compile_document(document, v2_spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json"))
        self.assertEqual(document, before)

    @settings(max_examples=200, deadline=None)
    @given(INVALID_TEXT)
    def test_invalid_headers_and_paths_are_rejected(self, value: str) -> None:
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy._header_name(value)
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy._path_patterns("/" + value)

    @settings(max_examples=200, deadline=None)
    @given(INVALID_ID)
    def test_activation_rejects_invalid_identifiers(self, value: str) -> None:
        with self.assertRaises(activation.ActivationProjectionError):
            activation.socket_path(value, "web")

    @settings(max_examples=200, deadline=None)
    @given(INVALID_TEXT)
    def test_secret_and_username_rejections_are_explicit(self, value: str) -> None:
        with self.assertRaises(setup_config.SetupError):
            setup_config.normalize_secret_line(value, "generated secret")
        with self.assertRaises(syncthing.DeviceError):
            syncthing.validate_username(value)

    @settings(max_examples=200, deadline=None)
    @given(INVALID_TEXT)
    def test_group_header_fails_closed(self, value: str) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(common.split_groups(value), set())

    @settings(max_examples=200, deadline=None)
    @given(TEXT)
    def test_structured_secrets_are_redacted_without_mutating_input(self, secret: str) -> None:
        raw = {"password": secret, "nested": {"token": secret}, "status": "failed"}
        before = copy.deepcopy(raw)
        sanitized = nas_logging.sanitize(raw)
        self.assertEqual(raw, before)
        self.assertEqual(sanitized["password"], "[redacted]")
        self.assertEqual(sanitized["nested"]["token"], "[redacted]")
        self.assertEqual(sanitized["status"], "failed")

    def test_valid_controls_are_accepted(self):
        compiled = v2_spec.compile_document(
            BASE_V2_DOCUMENT, v2_spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
        )
        self.assertEqual(compiled["derived"]["runtime"]["demo"]["ownerUnit"], "demo.service")
        self.assertEqual(caddy._header_name("X-Custom"), "X-Custom")
        self.assertEqual(setup_config.normalize_secret_line("literal", "secret"), "literal")


if __name__ == "__main__":
    unittest.main()
