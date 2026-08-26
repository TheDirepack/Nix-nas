from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_cli as cli  # noqa: E402


class V2CliTests(unittest.TestCase):
    def test_installed_program_name_is_stable(self) -> None:
        self.assertEqual(cli._parser().prog, "nas-v2")

    def write_spec(self, root: pathlib.Path) -> pathlib.Path:
        path = root / "services.yaml"
        path.write_text(
            """schemaVersion: 3
services:
  demo:
    name: Demo
    workload: {kind: daemon}
    runtime: {type: systemd, unit: demo.service}
""",
            encoding="utf-8",
        )
        return path

    def invoke(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = cli.main(argv)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_help_does_not_import_compiler_modules(self) -> None:
        with mock.patch.dict(sys.modules, {"nas_v2_apply": None, "nas_v2_spec": None}, clear=False):
            with self.assertRaises(SystemExit) as raised:
                cli.main(["--help"])
        self.assertEqual(raised.exception.code, 0)

    def test_validate_effective_and_plan_are_offline(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            for command in ("validate", "effective", "plan"):
                with self.subTest(command=command):
                    status, output, error = self.invoke(
                        [command, "--spec", str(spec), "--schema", str(SCHEMA), "--no-platform"]
                    )
                    self.assertEqual(status, 0, error)
                    self.assertEqual(error, "")
                    value = json.loads(output)
                    if command == "validate":
                        self.assertEqual(value, {"ok": True, "schemaVersion": 3})
                    elif command == "effective":
                        self.assertEqual(value["services"]["demo"]["runtime"]["unit"], "demo.service")
                    else:
                        self.assertEqual(value["runtime"][0]["service"], "demo")

    def test_invalid_input_returns_machine_readable_error_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = root / "bad.yaml"
            spec.write_text("schemaVersion: 3\nservices: [\n", encoding="utf-8")
            output = root / "output.json"
            status, stdout, stderr = self.invoke(
                ["effective", "--spec", str(spec), "--schema", str(SCHEMA), "--no-platform", "--output", str(output)]
            )
            self.assertEqual(status, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(json.loads(stderr)["ok"], False)
            self.assertFalse(output.exists())

    def test_apply_delegates_to_normal_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            with mock.patch.object(cli, "_path_defaults", return_value=(spec, SCHEMA, None)):
                with mock.patch("nas_v2_entry.main", return_value=0) as entry:
                    status, output, error = self.invoke(
                        ["apply", "--spec", str(spec), "--schema", str(SCHEMA), "--no-platform"]
                    )
            self.assertEqual(status, 0)
            self.assertEqual(error, "")
            self.assertTrue(json.loads(output)["ok"])
            self.assertEqual(entry.call_count, 1)


if __name__ == "__main__":
    unittest.main()
