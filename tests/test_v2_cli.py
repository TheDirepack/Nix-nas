from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_cli as cli  # noqa: E402


class ManagedServicesV2CliTests(unittest.TestCase):
    def _files(self, root: pathlib.Path, text: str) -> tuple[pathlib.Path, pathlib.Path]:
        spec = root / "services.yaml"
        schema = root / "schema.json"
        spec.write_text(text, encoding="utf-8")
        schema.write_text(SCHEMA.read_text(encoding="utf-8"), encoding="utf-8")
        return spec, schema

    def test_validate_reports_machine_readable_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec, schema = self._files(
                pathlib.Path(tmp),
                "schemaVersion: 3\nservices: {}\n",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = cli.main(
                    [
                        "validate",
                        "--spec",
                        str(spec),
                        "--schema",
                        str(schema),
                        "--no-platform",
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"valid": True, "schemaVersion": 3, "generation": 1, "services": 0},
            )

    def test_plan_does_not_write_runtime_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            spec, schema = self._files(
                root,
                """schemaVersion: 3
services:
  demo:
    name: Demo
    workload: {kind: daemon, activation: persistent}
    runtime: {type: systemd, unit: demo.service}
""",
            )
            effective_path = root / "effective.json"
            plan_path = root / "plan.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = cli.main(
                    [
                        "plan",
                        "--spec",
                        str(spec),
                        "--schema",
                        str(schema),
                        "--no-platform",
                        "--effective",
                        str(effective_path),
                        "--plan",
                        str(plan_path),
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["runtime"][0]["service"], "demo")
            self.assertFalse(effective_path.exists())
            self.assertFalse(plan_path.exists())

    def test_apply_materializes_only_derived_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            spec, schema = self._files(root, "schemaVersion: 3\nservices: {}\n")
            effective_path = root / "effective.json"
            plan_path = root / "plan.json"
            with contextlib.redirect_stdout(io.StringIO()):
                status = cli.main(
                    [
                        "apply",
                        "--spec",
                        str(spec),
                        "--schema",
                        str(schema),
                        "--no-platform",
                        "--effective",
                        str(effective_path),
                        "--plan",
                        str(plan_path),
                    ]
                )
            self.assertEqual(status, 0)
            self.assertTrue(effective_path.exists())
            self.assertTrue(plan_path.exists())

    def test_json_errors_keep_field_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec, schema = self._files(
                pathlib.Path(tmp),
                "schemaVersion: 3\nservices:\n  Bad_ID: {}\n",
            )
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                status = cli.main(
                    [
                        "--json-errors",
                        "validate",
                        "--spec",
                        str(spec),
                        "--schema",
                        str(schema),
                        "--no-platform",
                    ]
                )
            self.assertEqual(status, 2)
            payload = json.loads(error.getvalue())
            self.assertEqual(payload["code"], "schema-validation")
            self.assertTrue(payload["path"].startswith("$"))


if __name__ == "__main__":
    unittest.main()
