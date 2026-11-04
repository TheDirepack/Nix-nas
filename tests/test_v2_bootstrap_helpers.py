from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_bootstrap as bootstrap  # noqa: E402


class BootstrapLoadTests(unittest.TestCase):
    def test_load_rejects_a_non_mapping_document(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "list.yaml"
            path.write_text("- a\n- b\n", encoding="utf-8")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "must contain a YAML mapping"):
                bootstrap._load(path)

    def test_load_reports_an_unreadable_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(bootstrap.BootstrapError, "unable to read"):
                bootstrap._load(pathlib.Path(raw) / "absent.yaml")

    def test_yaml_files_of_a_missing_directory_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.assertEqual(bootstrap._yaml_files(pathlib.Path(raw) / "absent"), [])

    def test_is_directory_desired_uses_the_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            self.assertTrue(bootstrap._is_directory_desired(root / "services"))
            self.assertFalse(bootstrap._is_directory_desired(root / "services.yaml"))

    def test_load_desired_merges_directory_documents(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = pathlib.Path(raw) / "desired"
            desired.mkdir()
            (desired / "00-default.yaml").write_text(
                "schemaVersion: 3\nservices:\n  demo:\n    enabled: true\n", encoding="utf-8"
            )
            (desired / "01-extra.yaml").write_text(
                "services:\n  demo:\n    mode: host\n  other:\n    enabled: false\n", encoding="utf-8"
            )
            (desired / "notes.txt").write_text("ignored\n", encoding="utf-8")
            merged = bootstrap._load_desired(desired)
        self.assertEqual(merged["schemaVersion"], 3)
        # Merge is per top-level key: a later document replaces that key's value.
        self.assertEqual(merged["services"]["demo"], {"mode": "host"})
        self.assertEqual(merged["services"]["other"], {"enabled": False})

    def test_load_desired_replaces_a_scalar_with_a_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = pathlib.Path(raw) / "desired"
            desired.mkdir()
            (desired / "00-default.yaml").write_text("services: disabled\n", encoding="utf-8")
            (desired / "01-extra.yaml").write_text("services:\n  demo:\n    enabled: true\n", encoding="utf-8")
            merged = bootstrap._load_desired(desired)
        self.assertEqual(merged["services"], {"demo": {"enabled": True}})

    def test_load_desired_empty_directory_returns_a_v3_stub(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = pathlib.Path(raw) / "desired"
            desired.mkdir()
            stub = bootstrap._load_desired(desired)
        self.assertEqual(stub["schemaVersion"], 3)
        self.assertEqual(dict(stub["services"]), {})

    def test_load_desired_absent_directory_returns_a_v3_stub(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stub = bootstrap._load_desired(pathlib.Path(raw) / "desired")
        self.assertEqual(stub["schemaVersion"], 3)

    def test_load_desired_plain_file_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "services.yaml"
            path.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            loaded = bootstrap._load_desired(path)
        self.assertEqual(loaded["schemaVersion"], 3)

    def test_clear_marker_removes_the_file_and_tolerates_absence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker = pathlib.Path(raw) / "seeded"
            marker.write_text("1\n", encoding="utf-8")
            bootstrap._clear_marker(marker)
            self.assertFalse(marker.exists())
            bootstrap._clear_marker(marker)


class BootstrapAtomicDumpTests(unittest.TestCase):
    def test_directory_target_writes_one_default_document(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            desired = pathlib.Path(raw) / "desired"
            desired.mkdir()
            document = bootstrap.CommentedMap()
            document["schemaVersion"] = 3
            document["services"] = bootstrap.CommentedMap()
            bootstrap._atomic_dump_desired(desired, document)
            self.assertTrue((desired / "00-default.yaml").is_file())

    def test_file_target_is_written_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = pathlib.Path(raw) / "services.yaml"
            document = bootstrap.CommentedMap()
            document["schemaVersion"] = 3
            document["services"] = bootstrap.CommentedMap()
            bootstrap._atomic_dump_desired(target, document)
            self.assertTrue(target.is_file())
            self.assertIn("schemaVersion", target.read_text(encoding="utf-8"))


class BootstrapSeedDetectionTests(unittest.TestCase):
    def test_seed_stub_requires_the_generated_shape(self) -> None:
        stub = bootstrap.CommentedMap()
        stub["schemaVersion"] = 3
        stub["services"] = bootstrap.CommentedMap()
        self.assertTrue(bootstrap._is_seed_stub(stub))

        operator = bootstrap.CommentedMap()
        operator["schemaVersion"] = 3
        operator["services"] = bootstrap.CommentedMap()
        operator["services"]["demo"] = {"enabled": True}
        self.assertFalse(bootstrap._is_seed_stub(operator))


if __name__ == "__main__":
    unittest.main()
