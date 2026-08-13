from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_common as common  # noqa: E402


class CommonDriftCoverageTests(unittest.TestCase):
    def test_run_command_timeout_without_secret_reports_timeout(self) -> None:
        result = common.run_command(
            [sys.executable, "-c", "import time; print('before', flush=True); time.sleep(5)"],
            timeout_seconds=0.05,
        )
        self.assertEqual(result.returncode, 124)
        self.assertIn("before", result.stdout)
        self.assertEqual(result.stderr, "Command timed out")

    def test_run_command_timeout_with_secret_redacts_all_child_output(self) -> None:
        result = common.run_command(
            [sys.executable, "-c", "import sys,time; print(sys.stdin.read(), flush=True); time.sleep(5)"],
            input_text="protected-value",
            timeout_seconds=0.05,
        )
        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Command timed out after receiving protected standard input")
        self.assertNotIn("protected-value", result.stderr)

    def test_run_command_capture_false_and_environment_overlay(self) -> None:
        result = common.run_command(
            [
                sys.executable,
                "-c",
                "import os; raise SystemExit(0 if os.environ.get('NAS_TEST_OVERLAY') == 'yes' else 3)",
            ],
            env={"NAS_TEST_OVERLAY": "yes"},
            capture=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_run_command_zero_output_limit_marks_truncation(self) -> None:
        result = common.run_command(
            [sys.executable, "-c", "import sys; print('stdout'); print('stderr', file=sys.stderr)"],
            max_output_bytes=0,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "\n[output truncated]")
        self.assertEqual(result.stderr, "\n[output truncated]")

    def test_parse_systemd_show_ignores_lines_without_separator_and_records_without_id(self) -> None:
        parsed = common.parse_systemd_show(
            "junk\nActiveState=active\n\nId=good.service\nline-without-equals\nSubState=running\n"
        )
        self.assertEqual(set(parsed), {"good.service"})
        self.assertEqual(parsed["good.service"]["SubState"], "running")

    def test_read_json_object_warns_and_returns_fallback_for_invalid_json_and_io_errors(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            warnings: list[str] = []
            invalid = root / "invalid.json"
            invalid.write_text("{", encoding="utf-8")
            self.assertEqual(
                common.read_json_object(invalid, missing={"safe": False}, warn=warnings.append),
                {"safe": False},
            )
            directory = root / "directory"
            directory.mkdir()
            self.assertEqual(
                common.read_json_object(directory, missing={"safe": False}, warn=warnings.append),
                {"safe": False},
            )
            self.assertEqual(len(warnings), 2)

    def test_read_json_object_raises_invalid_json_without_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "invalid.json"
            path.write_text(json.dumps([]), encoding="utf-8")
            with self.assertRaises(ValueError):
                common.read_json_object(path)

    def test_application_capability_group_accepts_longest_valid_identifiers(self) -> None:
        service_id = "a" + "1" * 63
        capability = "a" + ".1" * 63
        rendered = common.application_capability_group(service_id, capability)
        self.assertEqual(rendered, f"application.{service_id}.{capability}")


if __name__ == "__main__":
    unittest.main()
