from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

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

    def test_rollback_does_not_overwrite_newer_edit(self):
        # Simulate: A writes rev2, reconcile fails, B writes rev3, A rollback should not overwrite rev3
        import nas_v2_control as control

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            p = root / "services.yaml"
            # patch control's DESIRED_PATH and RECONCILE_UNIT
            orig_desired = control.DESIRED_PATH
            orig_reconcile = control.RECONCILE_UNIT
            try:
                control.DESIRED_PATH = p
                # use a fake systemctl that fails
                control.RECONCILE_UNIT = "fake-reconcile-unit"

                # initial
                p.write_text(minimal_yaml("a"), encoding="utf-8")
                previous = p.read_text(encoding="utf-8")
                # A writes rev2
                yaml2 = minimal_yaml("b")
                editor.replace_document(yaml2, desired_path=p, schema_path=SCHEMA, platform_path=None)
                attempted = p.read_text(encoding="utf-8")
                # B writes rev3
                yaml3 = minimal_yaml("c")
                p.write_text(yaml3, encoding="utf-8")
                # A rollback should detect superseded and not overwrite
                with self.assertRaisesRegex(control.ControlError, "already superseded"):
                    control._rollback(previous, attempted, RuntimeError("reconcile failed"))
                self.assertEqual(p.read_text(encoding="utf-8"), yaml3)
            finally:
                control.DESIRED_PATH = orig_desired
                control.RECONCILE_UNIT = orig_reconcile


if __name__ == "__main__":
    unittest.main()
