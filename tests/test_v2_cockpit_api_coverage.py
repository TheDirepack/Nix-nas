from __future__ import annotations

import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_cockpit_api as api  # noqa: E402
from nas_common import CommandResult  # noqa: E402


class CockpitApiCoverageTests(unittest.TestCase):
    def test_json_command_optional_and_strict_failures(self) -> None:
        failed = CommandResult(("tool",), 1, "", "bad")
        with mock.patch.object(api, "run", return_value=failed):
            optional = api._json_command(["tool"], optional=True)
            self.assertFalse(optional["ok"])
            with self.assertRaises(api.ApiError):
                api._json_command(["tool"])
        invalid = CommandResult(("tool",), 0, "{", "")
        with mock.patch.object(api, "run", return_value=invalid):
            self.assertFalse(api._json_command(["tool"], optional=True)["ok"])
            with self.assertRaisesRegex(api.ApiError, "invalid JSON"):
                api._json_command(["tool"])
        sequence = CommandResult(("tool",), 0, "[]", "")
        with mock.patch.object(api, "run", return_value=sequence):
            self.assertFalse(api._json_command(["tool"], optional=True)["ok"])
            with self.assertRaisesRegex(api.ApiError, "invalid data"):
                api._json_command(["tool"])

    def test_json_input_enforces_size_encoding_and_object_shape(self) -> None:
        class Buffer:
            def __init__(self, payload: bytes):
                self.buffer = io.BytesIO(payload)

        with mock.patch.object(api.sys, "stdin", Buffer(b'{"x":1}')):
            self.assertEqual(api._json_input(), {"x": 1})
        with mock.patch.object(api.sys, "stdin", Buffer(b"[]")):
            with self.assertRaisesRegex(api.ApiError, "must be an object"):
                api._json_input()
        with mock.patch.object(api.sys, "stdin", Buffer(b"\xff")):
            with self.assertRaisesRegex(api.ApiError, "Invalid JSON"):
                api._json_input()
        with mock.patch.object(api.sys, "stdin", Buffer(b"x" * (api.MAX_JSON_INPUT_BYTES + 1))):
            with self.assertRaisesRegex(api.ApiError, "input limit"):
                api._json_input()

    def test_json_string_and_list_validation(self) -> None:
        self.assertEqual(api._json_string({"name": "value"}, "name", required=True), "value")
        for value in (1, "x\x00y", "x" * 5):
            with self.subTest(value=value), self.assertRaises(api.ApiError):
                api._json_string({"name": value}, "name", max_length=4)
        with self.assertRaisesRegex(api.ApiError, "required"):
            api._json_string({}, "name", required=True)
        self.assertEqual(api._json_string_list({"models": ["a", "b"]}, "models"), ["a", "b"])
        for value in ("a", [""], [1]):
            with self.subTest(value=value), self.assertRaises(api.ApiError):
                api._json_string_list({"models": value}, "models")
        with self.assertRaisesRegex(api.ApiError, "required"):
            api._json_string_list({}, "models", required=True)

    def test_service_states_handles_empty_command_failure_and_memory_values(self) -> None:
        self.assertEqual(api.service_states([]), {})
        with mock.patch.object(api, "run", return_value=CommandResult((), 1, "", "")):
            self.assertEqual(api.service_states(["a.service"]), {})
        output = "\n".join(
            [
                "Id=a.service",
                "LoadState=loaded",
                "ActiveState=active",
                "SubState=running",
                "UnitFileState=enabled",
                "MemoryCurrent=123",
                "Result=success",
                "",
                "Id=b.service",
                "LoadState=loaded",
                "ActiveState=inactive",
                "MemoryCurrent=bad",
                "",
            ]
        )
        with mock.patch.object(api, "run", return_value=CommandResult((), 0, output, "")):
            states = api.service_states(["a.service", "b.service"])
        self.assertEqual(states["a.service"]["memoryBytes"], 123)
        self.assertIsNone(states["b.service"]["memoryBytes"])

    def test_managed_services_status_failures_and_success(self) -> None:
        with mock.patch.object(api, "run", return_value=CommandResult((), 1, "", "bad")):
            self.assertFalse(api.managed_services_status()["ok"])
        with mock.patch.object(api, "run", return_value=CommandResult((), 0, "{", "")):
            self.assertIn("invalid JSON", api.managed_services_status()["error"])
        with mock.patch.object(api, "run", return_value=CommandResult((), 0, "{}", "")):
            self.assertIn("no service list", api.managed_services_status()["error"])
        with mock.patch.object(api, "run", return_value=CommandResult((), 0, '{"services":[],"ok":false}', "")):
            self.assertFalse(api.managed_services_status()["ok"])
        with mock.patch.object(api, "run", return_value=CommandResult((), 0, '{"services":[]}', "")):
            self.assertTrue(api.managed_services_status()["ok"])

    def test_portal_entries_fail_closed_on_schema_and_urls(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "portal.json"
            with mock.patch.object(api, "PORTAL_MODEL", path):
                self.assertEqual(api.portal_entries(), [])
                path.write_text("{", encoding="utf-8")
                self.assertEqual(api.portal_entries(), [])
                path.write_text('{"schemaVersion":1,"source":"managed-services-v2","entries":[]}', encoding="utf-8")
                self.assertEqual(api.portal_entries(), [])
                path.write_text('{"schemaVersion":2,"source":"managed-services-v2","entries":{}}', encoding="utf-8")
                self.assertEqual(api.portal_entries(), [])
                path.write_text(
                    json.dumps(
                        {
                            "schemaVersion": 2,
                            "source": "managed-services-v2",
                            "entries": [
                                "bad",
                                {"url": "https://external.example"},
                                {"url": "//host/path"},
                                {"url": "/bad\npath"},
                                {"url": "/good", "name": "Good"},
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                self.assertEqual(api.portal_entries(), [{"url": "/good", "name": "Good"}])


if __name__ == "__main__":
    unittest.main()
