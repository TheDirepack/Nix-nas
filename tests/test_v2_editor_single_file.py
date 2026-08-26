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


class V2SingleFileEditorTests(unittest.TestCase):
    def desired(self, root: pathlib.Path) -> pathlib.Path:
        path = root / "services.yaml"
        path.write_text(
            "# operator comment survives field edits\n"
            "schemaVersion: 3\n"
            "services:\n"
            "  demo:\n"
            "    name: Demo\n"
            "    workload:\n"
            "      kind: daemon\n"
            "      idleSeconds: 60\n"
            "    runtime:\n"
            "      type: systemd\n"
            "      unit: demo.service\n",
            encoding="utf-8",
        )
        return path

    def test_field_edit_round_trips_existing_comments(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = self.desired(root)
            editor.set_service_mode(
                "demo",
                "on-demand",
                desired_path=desired,
                schema_path=SCHEMA,
                platform_path=None,
            )
            text = desired.read_text(encoding="utf-8")
            self.assertIn("# operator comment survives field edits", text)
            self.assertIn("activation: on-demand", text)

    def test_schema_form_replacement_emits_only_canonical_nix_nas_preamble(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = self.desired(root)
            document = editor.read_document(desired_path=desired, schema_path=SCHEMA)["document"]
            document["services"]["demo"]["name"] = "Changed"
            editor.replace_document_value(
                document,
                desired_path=desired,
                schema_path=SCHEMA,
                platform_path=None,
            )
            text = desired.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("# Nix NAS Managed Services V2\n"))
            self.assertIn("Git stores its history", text)
            self.assertNotIn("operator comment survives field edits", text)
            self.assertIn("name: Changed", text)

    def test_directory_authority_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = pathlib.Path(raw) / "services"
            desired.mkdir()
            with self.assertRaisesRegex(editor.ManagedServicesEditorError, "one YAML file"):
                editor.read_document(desired_path=desired, schema_path=SCHEMA)


if __name__ == "__main__":
    unittest.main()
