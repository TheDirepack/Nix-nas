from __future__ import annotations

import json
import pathlib
import sqlite3
import stat
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_backup_verify as verifier  # noqa: E402


class V2BackupVerifyTests(unittest.TestCase):
    def write_inventory(self, root: pathlib.Path, resources: list[dict]) -> pathlib.Path:
        path = root / "inventory.json"
        path.write_text(json.dumps({"schemaVersion": 1, "resources": resources}), encoding="utf-8")
        return path

    def fake_pg_restore(self, root: pathlib.Path, *, succeeds: bool = True) -> str:
        path = root / "pg_restore"
        if succeeds:
            path.write_text("#!/bin/sh\necho '1; 0 0 TABLE public example postgres'\n", encoding="utf-8")
        else:
            path.write_text("#!/bin/sh\necho broken >&2\nexit 1\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def test_native_dump_uses_generic_format_integrity_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            artifact = restore / "run" / "backup" / "example"
            artifact.mkdir(parents=True)

            database = artifact / "state.db"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE item (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
                connection.execute("INSERT INTO item(value) VALUES ('ok')")

            (artifact / "opaque-native-artifact").write_text("application-owned\n", encoding="utf-8")
            (artifact / "database.pgdump").write_bytes(b"PGDMPfixture")
            inventory = self.write_inventory(
                root,
                [
                    {
                        "id": "example-state",
                        "path": "/var/lib/example",
                        "consistency": "native-dump",
                        "nativeDump": {"artifactPath": "/run/backup/example"},
                    }
                ],
            )

            result = verifier.verify(
                inventory_path=inventory,
                restore_root=restore,
                pg_restore_bin=self.fake_pg_restore(root),
            )

            checks = result["resources"][0]["checks"]
            self.assertEqual(checks, {"sqlite": 1, "postgresqlCustom": 1})
            self.assertEqual(result["resources"][0]["files"], 3)

    def test_arbitrary_filesystem_content_is_not_traversed_or_format_interpreted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            data = restore / "tank" / "documents"
            data.mkdir(parents=True)
            (data / "deliberately-malformed.xml").write_text("<not-closed>", encoding="utf-8")
            inventory = self.write_inventory(
                root,
                [{"id": "documents", "path": "/tank/documents", "consistency": "filesystem"}],
            )

            result = verifier.verify(
                inventory_path=inventory,
                restore_root=restore,
                pg_restore_bin=self.fake_pg_restore(root),
            )

            self.assertEqual(result["resources"][0]["checks"], {"sqlite": 0, "postgresqlCustom": 0})
            self.assertEqual(result["resources"][0]["files"], 0)

    def test_missing_resource_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            restore.mkdir()
            inventory = self.write_inventory(
                root,
                [{"id": "missing", "path": "/tank/missing", "consistency": "filesystem"}],
            )
            with self.assertRaisesRegex(verifier.BackupVerificationError, "missing"):
                verifier.verify(
                    inventory_path=inventory,
                    restore_root=restore,
                    pg_restore_bin=self.fake_pg_restore(root),
                )

    def test_empty_native_dump_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            artifact = restore / "run" / "backup" / "empty"
            artifact.mkdir(parents=True)
            (artifact / "empty").touch()
            inventory = self.write_inventory(
                root,
                [
                    {
                        "id": "empty-state",
                        "path": "/var/lib/empty",
                        "consistency": "native-dump",
                        "nativeDump": {"artifactPath": "/run/backup/empty"},
                    }
                ],
            )
            with self.assertRaisesRegex(verifier.BackupVerificationError, "no non-empty"):
                verifier.verify(
                    inventory_path=inventory,
                    restore_root=restore,
                    pg_restore_bin=self.fake_pg_restore(root),
                )

    def test_native_dump_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            artifact = restore / "run" / "backup" / "links"
            artifact.mkdir(parents=True)
            outside = root / "outside"
            outside.write_text("do not inspect\n", encoding="utf-8")
            (artifact / "escape").symlink_to(outside)
            inventory = self.write_inventory(
                root,
                [
                    {
                        "id": "linked-state",
                        "path": "/var/lib/linked",
                        "consistency": "native-dump",
                        "nativeDump": {"artifactPath": "/run/backup/links"},
                    }
                ],
            )
            with self.assertRaisesRegex(verifier.BackupVerificationError, "contains a symlink"):
                verifier.verify(
                    inventory_path=inventory,
                    restore_root=restore,
                    pg_restore_bin=self.fake_pg_restore(root),
                )

    def test_corrupt_sqlite_native_dump_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            artifact = restore / "run" / "backup" / "corrupt"
            artifact.mkdir(parents=True)
            (artifact / "state.db").write_bytes(b"SQLite format 3\x00not-a-database")
            inventory = self.write_inventory(
                root,
                [
                    {
                        "id": "corrupt-state",
                        "path": "/var/lib/corrupt",
                        "consistency": "native-dump",
                        "nativeDump": {"artifactPath": "/run/backup/corrupt"},
                    }
                ],
            )
            with self.assertRaisesRegex(verifier.BackupVerificationError, "SQLite integrity"):
                verifier.verify(
                    inventory_path=inventory,
                    restore_root=restore,
                    pg_restore_bin=self.fake_pg_restore(root),
                )

    def test_postgresql_dump_failure_is_reported_without_application_knowledge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            artifact = restore / "run" / "backup" / "postgres"
            artifact.mkdir(parents=True)
            (artifact / "database.dump").write_bytes(b"PGDMPfixture")
            inventory = self.write_inventory(
                root,
                [
                    {
                        "id": "relational-state",
                        "path": "/var/lib/relational",
                        "consistency": "native-dump",
                        "nativeDump": {"artifactPath": "/run/backup/postgres"},
                    }
                ],
            )
            with self.assertRaisesRegex(verifier.BackupVerificationError, "PostgreSQL custom dump"):
                verifier.verify(
                    inventory_path=inventory,
                    restore_root=restore,
                    pg_restore_bin=self.fake_pg_restore(root, succeeds=False),
                )

    def test_zfs_snapshot_resource_is_found_beneath_restored_snapshot_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore = root / "restore"
            snapshot = restore / "tank" / "projects" / ".zfs" / "snapshot" / "nas-v2-restic-test"
            snapshot.mkdir(parents=True)
            (snapshot / "project.txt").write_text("restored\n", encoding="utf-8")
            inventory = self.write_inventory(
                root,
                [
                    {
                        "id": "projects",
                        "path": "/tank/projects",
                        "dataset": "tank/projects",
                        "consistency": "zfs-snapshot",
                    }
                ],
            )

            result = verifier.verify(
                inventory_path=inventory,
                restore_root=restore,
                pg_restore_bin=self.fake_pg_restore(root),
            )
            self.assertEqual(result["resources"][0]["files"], 0)
            self.assertEqual(result["resources"][0]["sources"], [str(snapshot)])


if __name__ == "__main__":
    unittest.main()
