from __future__ import annotations

import errno
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import nas_v2_backup as backup
import test_v2_backup_runtime as fixtures


class BackupExecutionErrorTests(unittest.TestCase):
    def runtime_error(self, call) -> backup.BackupRuntimeError:
        try:
            call()
        except backup.BackupRuntimeError as exc:
            return exc
        except OSError as exc:
            self.fail(f"execution error escaped the backup runtime boundary: {exc}")
        self.fail("backup command unexpectedly succeeded")

    def test_missing_binary_is_a_runtime_error_with_its_original_cause(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            error = self.runtime_error(lambda: backup._run([str(pathlib.Path(raw) / "missing-zfs")]))
        self.assertIsInstance(error.__cause__, FileNotFoundError)
        self.assertIn("unable to execute", str(error))

    def test_permission_failure_is_a_runtime_error_with_its_original_cause(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            program = pathlib.Path(raw) / "not-executable"
            program.write_text("fixture")
            program.chmod(0o600)
            error = self.runtime_error(lambda: backup._run([str(program)]))
        self.assertIsInstance(error.__cause__, PermissionError)

    def test_missing_zfs_binary_is_not_proof_that_a_snapshot_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.runtime_error(
                lambda: backup._zfs_snapshot_exists(str(pathlib.Path(raw) / "missing-zfs"), "tank/data@fixture")
            )

    def test_native_absence_response_still_means_absent(self) -> None:
        result = subprocess.CompletedProcess(["fixture-zfs"], 1, stdout="", stderr="dataset does not exist")
        with mock.patch.object(backup.subprocess, "run", return_value=result):
            self.assertFalse(backup._zfs_snapshot_exists("fixture-zfs", "tank/data@fixture"))

    def test_cleanup_continues_artifacts_and_retains_unverified_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            staging = root / "staging"
            artifact = staging / "database-artifact"
            artifact.mkdir(parents=True)
            (artifact / "dump").write_bytes(b"fixture")
            outside = root / "outside"
            outside.write_bytes(b"must survive")
            state, paths = root / "state.json", root / "paths"
            snapshots = [{"dataset": "tank/data", "name": "first"}, {"dataset": "tank/data", "name": "second"}]
            state.write_text(
                json.dumps(
                    {"schemaVersion": 1, "snapshots": snapshots, "nativeDumps": [{"artifactPath": str(artifact)}]}
                )
            )
            paths.write_text("stale")
            with mock.patch.object(backup, "BACKUP_STAGING_ROOT", staging):
                error = self.runtime_error(
                    lambda: backup.cleanup(state_path=state, paths_path=paths, zfs_bin=str(root / "missing-zfs"))
                )
            self.assertFalse(artifact.exists())
            self.assertEqual(outside.read_bytes(), b"must survive")
            remaining = json.loads(state.read_text())
            self.assertEqual(remaining["snapshots"], snapshots)
            self.assertEqual(remaining["nativeDumps"], [])
            self.assertTrue(paths.exists())
            self.assertIn("tank/data@first", str(error))
            self.assertIn("tank/data@second", str(error))
            self.assertIn("absence probe failed", str(error))

    def test_prepare_keeps_primary_error_and_finishes_artifact_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            staging = root / "staging"
            artifact = staging / "database-artifact"
            inventory = fixtures.V2BackupRuntimeTests().inventory(artifact)
            inventory["resources"] += [
                {"id": "data", "path": "/fixture/data", "dataset": "tank/data", "consistency": "zfs-snapshot"},
                {"id": "invalid", "path": "/fixture/invalid", "consistency": "invalid"},
            ]
            inventory_path, state, paths = root / "inventory.json", root / "state.json", root / "paths"
            inventory_path.write_text(json.dumps(inventory))
            paths.write_text("stale")

            def command(argv, **_kwargs):
                if argv[0] == "fixture-systemctl":
                    (artifact / "dump").write_bytes(b"fresh")
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
                if argv[1] in {"destroy", "list"}:
                    raise FileNotFoundError(errno.ENOENT, "No such file or directory", argv[0])
                self.assertIn(argv[1], {"get", "snapshot"})
                return subprocess.CompletedProcess(
                    argv, 0, stdout="/fixture/data" if argv[1] == "get" else "", stderr=""
                )

            with (
                mock.patch.object(backup, "BACKUP_STAGING_ROOT", staging),
                mock.patch.object(backup.subprocess, "run", side_effect=command),
            ):
                error = self.runtime_error(
                    lambda: backup.prepare(
                        inventory_path=inventory_path,
                        state_path=state,
                        paths_path=paths,
                        zfs_bin="fixture-zfs",
                        systemctl_bin="fixture-systemctl",
                    )
                )
            self.assertIn("unsupported consistency 'invalid'", str(error))
            self.assertIn("unable to execute", str(error))
            self.assertIn("absence probe failed", str(error))
            self.assertFalse(artifact.exists())
            self.assertFalse(paths.exists())
            remaining = json.loads(state.read_text())
            self.assertEqual(len(remaining["snapshots"]), 1)
            self.assertEqual(remaining["nativeDumps"], [])
            self.assertIsInstance(error.__cause__, backup.BackupRuntimeError)
