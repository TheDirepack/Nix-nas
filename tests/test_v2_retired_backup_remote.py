from __future__ import annotations

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

import nas_v2_editor as editor  # noqa: E402
import nas_v2_spec as v2  # noqa: E402

DOCUMENT = {
    "schemaVersion": 3,
    "services": {
        "demo": {
            "name": "Demo",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "systemd", "unit": "demo.service"},
        }
    },
}
INERT_BLOCKS = (
    {},
    {"remote": {}},
    {"remote": {"provider": "local", "scope": "config-only", "rcloneRemote": ""}},
    {"remote": {"provider": "local", "scope": "config-only", "rcloneRemote": "", "rcloneConfigFile": ""}},
)
REQUESTING_BLOCKS = (
    {"remote": {"provider": "gdrive"}},
    {"remote": {"provider": "local", "scope": "all"}},
    {"remote": {"rcloneRemote": "s3:bucket/nas"}},
    {"remote": {"rcloneConfigFile": "/run/secrets/rclone.conf"}},
    {"remote": {"provider": "local", "unknown": True}},
    {"remote": "gdrive"},
    {"other": {}},
    "gdrive",
)


def compile_with(block: object) -> dict:
    document = {**json.loads(json.dumps(DOCUMENT)), "backup": block}
    return v2.compile_document(document, v2.load_schema(SCHEMA), platform_capabilities=None)


class RetiredBackupRemoteTests(unittest.TestCase):
    def test_schema_no_longer_offers_a_backup_destination(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertNotIn("backup", schema["properties"])
        effective = v2.compile_document(json.loads(json.dumps(DOCUMENT)), schema, platform_capabilities=None)
        self.assertNotIn("backup", effective)

    def test_inert_legacy_block_is_dropped(self) -> None:
        for block in INERT_BLOCKS:
            with self.subTest(block=block):
                effective = compile_with(block)
                self.assertNotIn("backup", effective)
                self.assertIn("demo", effective["services"])

    def test_requesting_a_remote_or_scope_is_rejected_with_the_migration(self) -> None:
        for block in REQUESTING_BLOCKS:
            with self.subTest(block=block):
                with self.assertRaises(v2.ManagedServicesV2Error) as raised:
                    compile_with(block)
                self.assertEqual(raised.exception.path, "$.backup")
                self.assertEqual(raised.exception.code, "retired-field")
                self.assertIn("nas.backup.repositoryFile", str(raised.exception))

    def test_retirement_does_not_mutate_the_caller_document(self) -> None:
        document = {**DOCUMENT, "backup": {"remote": {}}}
        result = v2.retire_backup_remote(document)
        self.assertIn("backup", document)
        self.assertNotIn("backup", result)
        self.assertIs(v2.retire_backup_remote(DOCUMENT), DOCUMENT)

    def write(self, root: pathlib.Path, backup_yaml: str) -> pathlib.Path:
        path = root / "services.yaml"
        path.write_text(
            "schemaVersion: 3\n"
            f"{backup_yaml}"
            "services:\n"
            "  demo:\n"
            "    name: Demo\n"
            "    workload: {kind: daemon}\n"
            "    runtime: {type: systemd, unit: demo.service}\n",
            encoding="utf-8",
        )
        return path

    def test_gui_form_omits_an_inert_block_and_saving_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = self.write(pathlib.Path(raw), "backup:\n  remote: {provider: local, scope: config-only}\n")
            document = editor.read_document(desired_path=desired, schema_path=SCHEMA)["document"]
            self.assertNotIn("backup", document)
            editor.replace_document_value(document, desired_path=desired, schema_path=SCHEMA, platform_path=None)
            self.assertNotIn("backup", desired.read_text(encoding="utf-8"))

    def test_existing_inert_authority_still_accepts_mode_changes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = self.write(pathlib.Path(raw), "backup:\n  remote: {provider: local}\n")
            editor.set_service_mode("demo", "off", desired_path=desired, schema_path=SCHEMA, platform_path=None)
            self.assertIn("enabled: false", desired.read_text(encoding="utf-8"))

    def test_requesting_block_stays_visible_and_blocks_saving(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = self.write(pathlib.Path(raw), "backup:\n  remote: {provider: gdrive, scope: all}\n")
            before = desired.read_text(encoding="utf-8")
            document = editor.read_document(desired_path=desired, schema_path=SCHEMA)["document"]
            self.assertEqual(document["backup"]["remote"]["provider"], "gdrive")
            with self.assertRaisesRegex(editor.ManagedServicesEditorError, r"\$\.backup.*repositoryFile"):
                editor.replace_document_value(document, desired_path=desired, schema_path=SCHEMA, platform_path=None)
            self.assertEqual(desired.read_text(encoding="utf-8"), before)


if __name__ == "__main__":
    unittest.main()
