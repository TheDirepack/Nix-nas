from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_editor as editor  # noqa: E402


class V2EditorTests(unittest.TestCase):
    def write_desired(self, root: pathlib.Path, *, idle: bool = True) -> pathlib.Path:
        path = root / "services.yaml"
        idle_line = "      idleSeconds: 300\n" if idle else ""
        path.write_text(
            "# operator comment must survive\n"
            "schemaVersion: 3\n"
            "services:\n"
            "  demo:\n"
            "    name: Demo\n"
            "    workload:\n"
            "      kind: daemon\n"
            f"{idle_line}"
            "    runtime:\n"
            "      type: systemd\n"
            "      unit: demo.service\n",
            encoding="utf-8",
        )
        return path

    def test_set_mode_preserves_comments_and_validates(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = self.write_desired(root)
            result = editor.set_service_mode(
                "demo",
                "on-demand",
                desired_path=desired,
                schema_path=ROOT / "schemas/managed-services-v3.schema.json",
                platform_path=None,
            )
            text = desired.read_text(encoding="utf-8")
            self.assertIn("# operator comment must survive", text)
            self.assertIn("activation: on-demand", text)
            self.assertEqual(result["effectiveMode"], "on-demand")

    def test_on_demand_requires_explicit_idle_policy(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = self.write_desired(root, idle=False)
            before = desired.read_text(encoding="utf-8")
            with self.assertRaisesRegex(editor.ManagedServicesEditorError, "idleSeconds"):
                editor.set_service_mode(
                    "demo",
                    "on-demand",
                    desired_path=desired,
                    schema_path=ROOT / "schemas/managed-services-v3.schema.json",
                    platform_path=None,
                )
            self.assertEqual(desired.read_text(encoding="utf-8"), before)

    def test_multi_service_edit_is_one_validated_write(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = self.write_desired(root)
            text = desired.read_text(encoding="utf-8") + (
                "  second:\n"
                "    name: Second\n"
                "    workload:\n"
                "      kind: daemon\n"
                "    runtime:\n"
                "      type: systemd\n"
                "      unit: second.service\n"
            )
            desired.write_text(text, encoding="utf-8")
            result = editor.set_service_modes(
                {"demo": "off", "second": "always"},
                desired_path=desired,
                schema_path=ROOT / "schemas/managed-services-v3.schema.json",
                platform_path=None,
            )
            self.assertEqual(result["changed"], ["demo", "second"])
            status = editor.status(
                desired_path=desired,
                effective_path=root / "missing-effective.json",
            )
            by_id = {row["id"]: row for row in status["services"]}
            self.assertEqual(by_id["demo"]["requestedMode"], "off")
            self.assertEqual(by_id["second"]["requestedMode"], "always")

    def test_scheduled_job_status_includes_generated_timer_units(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text(
                "schemaVersion: 3\n"
                "services:\n"
                "  backup:\n"
                "    name: Backup\n"
                "    workload:\n"
                "      kind: job\n"
                "      schedules:\n"
                "        - calendar: daily\n"
                "        - intervalSeconds: 3600\n"
                "    runtime:\n"
                "      type: systemd\n"
                "      unit: backup.service\n",
                encoding="utf-8",
            )
            result = editor.status(
                desired_path=desired,
                effective_path=root / "missing-effective.json",
            )
            backup = result["services"][0]
            self.assertEqual(
                backup["units"],
                [
                    {"unit": "backup.service", "role": "owner"},
                    {"unit": "nas-v2-timer-backup-0.timer", "role": "schedule"},
                    {"unit": "nas-v2-timer-backup-1.timer", "role": "schedule"},
                ],
            )


if __name__ == "__main__":
    unittest.main()
