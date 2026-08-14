from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_backup as runtime  # noqa: E402


class V2BackupRuntimeTests(unittest.TestCase):
    def inventory(self, artifact_path: pathlib.Path, *, resource_id: str = "database", artifact_resource: str = "database-artifact") -> dict:
        return {
            "schemaVersion": 1,
            "resources": [
                {
                    "id": resource_id,
                    "path": "/var/lib/example-db",
                    "consistency": "native-dump",
                    "nativeDump": {
                        "preparationService": "database-dump",
                        "preparationUnit": "nas-v2-database-dump.service",
                        "artifactResource": artifact_resource,
                        "artifactPath": str(artifact_path),
                    },
                }
            ],
        }

    def inventory_two(self, artifact_a: pathlib.Path, artifact_b: pathlib.Path) -> dict:
        return {
            "schemaVersion": 1,
            "resources": [
                {
                    "id": "first",
                    "path": "/var/lib/first-db",
                    "consistency": "native-dump",
                    "nativeDump": {
                        "preparationService": "first-dump",
                        "preparationUnit": "nas-v2-first-dump.service",
                        "artifactResource": "first-artifact",
                        "artifactPath": str(artifact_a),
                    },
                },
                {
                    "id": "second",
                    "path": "/var/lib/second-db",
                    "consistency": "native-dump",
                    "nativeDump": {
                        "preparationService": "second-dump",
                        "preparationUnit": "nas-v2-second-dump.service",
                        "artifactResource": "second-artifact",
                        "artifactPath": str(artifact_b),
                    },
                },
            ],
        }

    def _staging(self, root: pathlib.Path) -> pathlib.Path:
        # staging root derived from resource identity
        staging = root / "backup-staging"
        return staging

    def test_native_dump_restarts_job_and_publishes_artifact_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            artifact = staging / "database"
            # inventory uses resource_id database, artifactResource database-artifact, but path name database is allowed (matches resource_id)
            # To make it match artifactResource, use database-artifact name
            artifact = staging / "database-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")
            commands: list[list[str]] = []

            original_run = runtime._run
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging

            def fake_run(argv: list[str]) -> str:
                commands.append(argv)
                if argv == ["/bin/systemctl", "restart", "nas-v2-database-dump.service"]:
                    (artifact / "database.dump").write_bytes(b"fresh-dump")
                    return ""
                raise AssertionError(f"unexpected command: {argv}")

            runtime._run = fake_run
            try:
                result = runtime.prepare(
                    inventory_path=inventory_path,
                    paths_path=paths_path,
                    state_path=state_path,
                    zfs_bin="/bin/zfs",
                    systemctl_bin="/bin/systemctl",
                )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root

            self.assertEqual(commands, [["/bin/systemctl", "restart", "nas-v2-database-dump.service"]])
            self.assertEqual(paths_path.read_text(encoding="utf-8"), f"{artifact}\n")
            self.assertEqual(result["paths"], [str(artifact)])
            self.assertEqual(result["nativeDumps"][0]["artifactResource"], "database-artifact")
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["nativeDumps"], result["nativeDumps"])

    def test_empty_artifact_after_successful_job_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            artifact = staging / "database-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")

            original_run = runtime._run
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            runtime._run = lambda _argv: ""
            try:
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "completed without producing data"):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root

            self.assertTrue(artifact.is_dir())
            self.assertFalse(paths_path.exists())
            self.assertFalse(state_path.exists())

    def test_invalid_native_dump_mapping_never_executes_systemctl(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            inventory = self.inventory(staging / "database-artifact")
            del inventory["resources"][0]["nativeDump"]["preparationUnit"]
            inventory_path = root / "inventory.json"
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            called = False
            original_run = runtime._run
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging

            def fake_run(_argv: list[str]) -> str:
                nonlocal called
                called = True
                return ""

            runtime._run = fake_run
            try:
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "invalid compiled native-dump job mapping"):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=root / "paths.txt",
                        state_path=root / "state.json",
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(called)

    def test_stale_dump_is_not_accepted_when_job_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            artifact = staging / "database-artifact"
            staging.mkdir(parents=True, exist_ok=True)
            artifact.mkdir(parents=True)
            (artifact / "old.dump").write_bytes(b"old-data")
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")

            original_run = runtime._run
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            runtime._run = lambda _argv: ""
            try:
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "completed without producing data"):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            # stale dump should have been cleared, so artifact is empty after failure
            self.assertEqual(list(artifact.iterdir()), [])
            self.assertFalse(paths_path.exists())

    def test_artifact_outside_staging_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            outside = pathlib.Path(tmp) / "outside-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(outside)), encoding="utf-8")
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run
            runtime._run = lambda _argv: ""
            try:
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "escapes staging root|must be.*staging"):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root

    def test_symlink_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            staging.mkdir(parents=True, exist_ok=True)
            target = root / "real-target"
            target.mkdir()
            artifact = staging / "database-artifact"
            # create symlink that would escape
            try:
                artifact.symlink_to(target)
            except OSError:
                self.skipTest("symlink not supported")
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run
            runtime._run = lambda _argv: ""
            try:
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "must not be a symlink|escapes staging"):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
                if artifact.is_symlink():
                    artifact.unlink()

    def test_symlink_replacement_is_rejected_and_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            artifact = staging / "database-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run

            def fake_run(argv: list[str]) -> str:
                (artifact / "dump").write_bytes(b"data")
                return ""

            runtime._run = fake_run
            try:
                result = runtime.prepare(
                    inventory_path=inventory_path,
                    paths_path=paths_path,
                    state_path=state_path,
                    zfs_bin="/bin/zfs",
                    systemctl_bin="/bin/systemctl",
                )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            self.assertTrue(artifact.is_dir())
            # Replace artifact directory with symlink to outside
            outside = root / "outside"
            outside.mkdir()
            # remove artifact and replace with symlink
            # cleanup should handle symlink case
            import shutil
            shutil.rmtree(artifact)
            artifact.symlink_to(outside)
            # Now cleanup should remove symlink without following
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run
            runtime._run = lambda _argv: ""
            try:
                result2 = runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(artifact.exists() and artifact.is_symlink() and artifact.resolve() == outside.resolve())
            # symlink should be gone, outside should still exist
            self.assertTrue(outside.exists())
            self.assertFalse(state_path.exists())
            self.assertFalse(paths_path.exists())

    def test_later_resource_failure_cleans_previous_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            artifact_a = staging / "first-artifact"
            artifact_b = staging / "second-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory_two(artifact_a, artifact_b)), encoding="utf-8")
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run

            def fake_run(argv: list[str]) -> str:
                if argv == ["/bin/systemctl", "restart", "nas-v2-first-dump.service"]:
                    (artifact_a / "dump").write_bytes(b"first")
                    return ""
                if argv == ["/bin/systemctl", "restart", "nas-v2-second-dump.service"]:
                    raise runtime.BackupRuntimeError("second job failed")
                return ""

            runtime._run = fake_run
            try:
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "second job failed"):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            # first artifact should have been cleaned up on failure
            self.assertFalse(artifact_a.exists())
            # state and paths should be removed (partial failure cleanup)
            self.assertFalse(state_path.exists())
            self.assertFalse(paths_path.exists())

    def test_cleanup_removes_staged_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            artifact = staging / "database-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run

            def fake_run(argv: list[str]) -> str:
                (artifact / "dump").write_bytes(b"data")
                return ""

            runtime._run = fake_run
            try:
                runtime.prepare(
                    inventory_path=inventory_path,
                    paths_path=paths_path,
                    state_path=state_path,
                    zfs_bin="/bin/zfs",
                    systemctl_bin="/bin/systemctl",
                )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            self.assertTrue(artifact.is_dir())
            # Now cleanup
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            runtime._run = lambda _argv: ""
            try:
                result = runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(artifact.exists())
            self.assertFalse(state_path.exists())
            self.assertFalse(paths_path.exists())

    def test_cleanup_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            artifact = staging / "database-artifact"
            staging.mkdir(parents=True, exist_ok=True)
            artifact.mkdir(parents=True, exist_ok=True)
            (artifact / "file").write_bytes(b"x")
            state_path = root / "state.json"
            paths_path = root / "paths.txt"
            state = {
                "schemaVersion": 1,
                "snapshots": [],
                "nativeDumps": [
                    {
                        "source": "database",
                        "preparationService": "database-dump",
                        "preparationUnit": "nas-v2-database-dump.service",
                        "artifactResource": "database-artifact",
                        "artifactPath": str(artifact),
                    }
                ],
            }
            state_path.write_text(json.dumps(state), encoding="utf-8")
            paths_path.write_text(f"{artifact}\n", encoding="utf-8")
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run
            runtime._run = lambda _argv: ""
            # Make rmtree fail via mock
            with mock.patch("nas_v2_backup.shutil.rmtree", side_effect=OSError("permission denied")):
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "unable to clean native-dump artifact|failed to clean"):
                    runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            # state should still exist for retry
            self.assertTrue(state_path.exists())
            runtime.BACKUP_STAGING_ROOT = original_root
            runtime._run = original_run

    def test_repeated_cleanup_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = self._staging(root)
            artifact = staging / "database-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run

            def fake_run(argv: list[str]) -> str:
                (artifact / "dump").write_bytes(b"data")
                return ""

            runtime._run = fake_run
            try:
                runtime.prepare(
                    inventory_path=inventory_path,
                    paths_path=paths_path,
                    state_path=state_path,
                    zfs_bin="/bin/zfs",
                    systemctl_bin="/bin/systemctl",
                )
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            # first cleanup
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            runtime._run = lambda _argv: ""
            try:
                runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
                # second cleanup should be idempotent even though state gone
                result2 = runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
                self.assertEqual(result2["destroyed"], [])
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(state_path.exists())
            self.assertFalse(paths_path.exists())


if __name__ == "__main__":
    unittest.main()
