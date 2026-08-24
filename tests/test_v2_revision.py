from __future__ import annotations

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

import nas_v2_editor as editor  # noqa: E402


def minimal_yaml(name: str = "demo") -> str:
    return f"""schemaVersion: 3
services:
  {name}:
    name: Demo
    workload: {{kind: daemon}}
    runtime: {{type: systemd, unit: demo.service}}
"""


class RevisionTests(unittest.TestCase):
    def test_document_returns_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            p = root / "services.yaml"
            p.write_text(minimal_yaml(), encoding="utf-8")
            doc = editor.read_document(desired_path=p, schema_path=SCHEMA)
            self.assertIn("revision", doc)
            self.assertEqual(len(doc["revision"]), 64)

    def test_concurrent_stale_save_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            p = root / "services.yaml"
            p.write_text(minimal_yaml("a"), encoding="utf-8")
            rev1 = editor.read_document(desired_path=p, schema_path=SCHEMA)["revision"]
            # A saves rev2
            yaml2 = minimal_yaml("b")
            editor.replace_document(
                yaml2, desired_path=p, schema_path=SCHEMA, platform_path=None, expected_revision=rev1
            )
            rev2 = editor.read_document(desired_path=p, schema_path=SCHEMA)["revision"]
            self.assertNotEqual(rev1, rev2)
            # B tries to save using stale rev1 -> conflict
            yaml3 = minimal_yaml("c")
            with self.assertRaisesRegex(editor.ManagedServicesEditorError, "revision conflict"):
                editor.replace_document(
                    yaml3, desired_path=p, schema_path=SCHEMA, platform_path=None, expected_revision=rev1
                )
            # ensure rev3 not written
            self.assertEqual(editor.read_document(desired_path=p, schema_path=SCHEMA)["revision"], rev2)

    def test_control_does_not_restore_yaml_after_reconcile_failure(self):
        import nas_v2_control as control

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            p = root / "services.yaml"
            p.write_text(minimal_yaml("a"), encoding="utf-8")
            original_desired = control.DESIRED_PATH
            original_schema = control.SCHEMA_PATH
            original_platform = control.PLATFORM_PATH
            try:
                control.DESIRED_PATH = p
                control.SCHEMA_PATH = SCHEMA
                control.PLATFORM_PATH = None
                with mock.patch.object(control, "_reconcile", side_effect=control.ControlError("reconcile failed")):
                    with self.assertRaisesRegex(control.ControlError, "reconcile failed"):
                        control._mutate_and_reconcile(
                            lambda: editor.replace_document(
                                minimal_yaml("b"),
                                desired_path=p,
                                schema_path=SCHEMA,
                                platform_path=None,
                            )
                        )
                # Rollback belongs to the guarded Git reconcile transaction.
                # The control CLI must not race it by restoring prior text.
                self.assertEqual(p.read_text(encoding="utf-8"), minimal_yaml("b"))
                self.assertFalse(hasattr(control, "_rollback"))
            finally:
                control.DESIRED_PATH = original_desired
                control.SCHEMA_PATH = original_schema
                control.PLATFORM_PATH = original_platform


if __name__ == "__main__":
    unittest.main()
