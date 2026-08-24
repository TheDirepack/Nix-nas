from __future__ import annotations

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

import nas_v2_control as control  # noqa: E402


class ManagedServicesV2ControlTests(unittest.TestCase):
    def test_no_legacy_control_module_or_script_alias_exists(self):
        self.assertFalse((SERVICES / "nas_feature_control.py").exists())
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn("nas-feature-control", pyproject)
        self.assertIn('nas-managed-services-control = "nas_v2_control:main"', pyproject)

    def test_status_enriches_editor_rows_with_native_systemd_state(self):
        desired = {
            "ok": True,
            "schemaVersion": 3,
            "services": [
                {
                    "id": "demo",
                    "effective": True,
                    "effectiveMode": "always",
                    "units": [{"unit": "demo.service"}],
                }
            ],
        }
        snapshot = {
            "demo.service": {
                "ActiveState": "active",
                "SubState": "running",
                "MemoryCurrent": "4096",
            }
        }
        with (
            mock.patch.object(control, "desired_status", return_value=desired),
            mock.patch.object(control, "_unit_snapshot", return_value=snapshot),
        ):
            result = control.status()
        row = result["services"][0]
        self.assertTrue(row["running"])
        self.assertTrue(row["healthy"])
        self.assertEqual(row["units"][0]["memoryBytes"], 4096)
        self.assertNotIn("features", result)
        self.assertEqual(result["controller"], "managed-services-v2")

    def test_set_mode_reconciles_after_atomic_editor_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            desired_path = pathlib.Path(tmp) / "services.yaml"
            desired_path.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            with (
                mock.patch.object(control, "DESIRED_PATH", desired_path),
                mock.patch.object(control, "set_service_mode", return_value={"ok": True}) as setter,
                mock.patch.object(control, "_reconcile") as reconcile,
                mock.patch.object(control, "status", return_value={"ok": True}) as status,
            ):
                result = control.set_mode("demo", "always")
        setter.assert_called_once()
        reconcile.assert_called_once_with()
        status.assert_called_once_with()
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], {"ok": True})

    def test_failed_reconcile_is_reported_without_a_second_editor_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            desired_path = pathlib.Path(tmp) / "services.yaml"
            desired_path.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            with (
                mock.patch.object(control, "DESIRED_PATH", desired_path),
                mock.patch.object(control, "set_service_mode", return_value={"ok": True}),
                mock.patch.object(control, "replace_document") as replace,
                mock.patch.object(control, "_reconcile", side_effect=control.ControlError("activation failed")),
            ):
                with self.assertRaisesRegex(control.ControlError, "activation failed"):
                    control.set_mode("demo", "always")
        replace.assert_not_called()

    def test_document_and_replace_document_are_schema_driven_surfaces(self):
        with (
            mock.patch.object(
                control,
                "read_document",
                return_value={"yaml": "services: {}", "document": {"services": {}}, "schema": {}},
            ),
            mock.patch.object(control, "_reconcile") as reconcile,
        ):
            result = control.document()
            self.assertEqual(result["yaml"], "services: {}")
            self.assertEqual(result["document"], {"services": {}})
            reconcile.assert_not_called()

        with tempfile.TemporaryDirectory() as tmp:
            desired_path = pathlib.Path(tmp) / "services.yaml"
            source_path = pathlib.Path(tmp) / "replacement.yaml"
            desired_path.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            source_path.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            with (
                mock.patch.object(control, "DESIRED_PATH", desired_path),
                mock.patch.object(control, "replace_document", return_value={"ok": True}) as replace,
                mock.patch.object(control, "_reconcile") as reconcile,
            ):
                result = control.replace_from_source(str(source_path))
        self.assertTrue(result["ok"])
        replace.assert_called_once()
        reconcile.assert_called_once_with()

    def test_replace_json_document_uses_same_reconcile_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            desired_path = root / "services.yaml"
            source_path = root / "replacement.json"
            desired_path.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            source_value = {"schemaVersion": 3, "services": {}}
            source_path.write_text(json.dumps(source_value), encoding="utf-8")
            with (
                mock.patch.object(control, "DESIRED_PATH", desired_path),
                mock.patch.object(control, "replace_document_value", return_value={"ok": True}) as replace,
                mock.patch.object(control, "_reconcile") as reconcile,
            ):
                result = control.replace_json_from_source(str(source_path))
        self.assertTrue(result["ok"])
        replace.assert_called_once_with(
            source_value,
            desired_path=desired_path,
            schema_path=control.SCHEMA_PATH,
            platform_path=None,
        )
        reconcile.assert_called_once_with()

    def test_replace_json_document_rejects_non_object_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_path = pathlib.Path(tmp) / "replacement.json"
            source_path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(control.ControlError, "must contain an object"):
                control.replace_json_from_source(str(source_path))


if __name__ == "__main__":
    unittest.main()
