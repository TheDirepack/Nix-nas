from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
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
    def test_cleanup_rejects_staging_root_and_nested_paths_without_deleting_data(self):
        for target in ("root", "nested"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                staging = root / "backup-staging"
                other = staging / "other-artifact"
                other.mkdir(parents=True)
                sentinel = other / "dump"
                sentinel.write_bytes(b"must survive")
                artifact = staging if target == "root" else sentinel
                state_path, paths_path = root / "state.json", root / "paths.txt"
                entry = {"artifactPath": str(artifact)}
                state_path.write_text(json.dumps({"schemaVersion": 1, "snapshots": [], "nativeDumps": [entry]}))
                paths_path.write_text(str(artifact))
                with mock.patch.object(runtime, "BACKUP_STAGING_ROOT", staging):
                    with self.assertRaisesRegex(runtime.BackupRuntimeError, "staging root"):
                        runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/false")
                self.assertEqual(sentinel.read_bytes(), b"must survive")
                self.assertEqual(json.loads(state_path.read_text())["nativeDumps"], [entry])
                self.assertTrue(paths_path.exists())

    def test_cleanup_rejects_symlinked_staging_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            artifact = outside / "database-artifact"
            artifact.mkdir()
            sentinel = artifact / "dump"
            sentinel.write_bytes(b"must survive")
            staging = root / "backup-staging"
            staging.symlink_to(outside, target_is_directory=True)
            with mock.patch.object(runtime, "BACKUP_STAGING_ROOT", staging):
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "staging root.*symlink"):
                    runtime._remove_staged_artifact(str(staging / artifact.name))
            self.assertEqual(sentinel.read_bytes(), b"must survive")

    def test_preparation_job_cannot_publish_an_artifact_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "private.dump"
            sentinel.write_bytes(b"must not be backed up")
            inventory_path, paths_path, state_path = root / "inventory.json", root / "paths.txt", root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)))
            calls = []

            def replace_artifact(argv, **_kwargs):
                calls.append(argv)
                if argv == ["/bin/systemctl", "restart", "nas-v2-database-dump.service"]:
                    shutil.rmtree(artifact)
                    artifact.symlink_to(outside, target_is_directory=True)
                    return ""
                if argv == ["/bin/systemctl", "stop", "nas-v2-database-dump.service"]:
                    self.assertTrue(artifact.is_symlink())
                    self.assertEqual(
                        json.loads(state_path.read_text())["nativeDumps"][0]["artifactPath"], str(artifact)
                    )
                    return ""
                raise AssertionError(f"unexpected command: {argv}")

            with (
                mock.patch.object(runtime, "BACKUP_STAGING_ROOT", staging),
                mock.patch.object(runtime, "_run", side_effect=replace_artifact),
            ):
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "symlink"):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/false",
                        systemctl_bin="/bin/systemctl",
                    )
            self.assertEqual(
                calls,
                [
                    ["/bin/systemctl", "restart", "nas-v2-database-dump.service"],
                    ["/bin/systemctl", "stop", "nas-v2-database-dump.service"],
                ],
            )
            self.assertEqual(sentinel.read_bytes(), b"must not be backed up")
            self.assertFalse(artifact.exists())
            self.assertFalse(artifact.is_symlink())
            self.assertFalse(paths_path.exists())
            self.assertFalse(state_path.exists())

    def inventory(
        self,
        artifact_path: pathlib.Path,
        *,
        resource_id: str = "database",
        artifact_resource: str = "database-artifact",
    ) -> dict:
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

            def fake_run(argv: list[str], **_kwargs) -> str:
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
            runtime._run = lambda _argv, **_kwargs: ""
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

            self.assertFalse(artifact.exists())
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

            def fake_run(_argv: list[str], **_kwargs) -> str:
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
            runtime._run = lambda _argv, **_kwargs: ""
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
            # stale dump should have been cleared, so no artifact remains after failure
            self.assertFalse(artifact.exists())
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
            runtime._run = lambda _argv, **_kwargs: ""
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
            runtime._run = lambda _argv, **_kwargs: ""
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

            def fake_run(argv: list[str], **_kwargs) -> str:
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
            # Replace artifact directory with symlink to outside
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "private.dump"
            sentinel.write_bytes(b"outside data must survive")
            shutil.rmtree(artifact)
            artifact.symlink_to(outside)
            # Now cleanup should remove symlink without following
            original_root = runtime.BACKUP_STAGING_ROOT
            runtime.BACKUP_STAGING_ROOT = staging
            original_run = runtime._run
            runtime._run = lambda _argv, **_kwargs: ""
            try:
                runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            finally:
                runtime._run = original_run
                runtime.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(artifact.exists())
            self.assertFalse(artifact.is_symlink())
            self.assertEqual(sentinel.read_bytes(), b"outside data must survive")
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

            def fake_run(argv: list[str], **_kwargs) -> str:
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

            def fake_run(argv: list[str], **_kwargs) -> str:
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
            runtime._run = lambda _argv, **_kwargs: ""
            try:
                runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
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
            runtime._run = lambda _argv, **_kwargs: ""
            # Make rmtree fail via mock
            with mock.patch("nas_v2_backup.shutil.rmtree", side_effect=OSError("permission denied")):
                with self.assertRaisesRegex(
                    runtime.BackupRuntimeError, "unable to clean native-dump artifact|failed to clean"
                ):
                    runtime.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            # state should still exist for retry
            self.assertTrue(state_path.exists())
            runtime.BACKUP_STAGING_ROOT = original_root
            runtime._run = original_run

    def test_failed_native_stop_preserves_artifact_and_outstanding_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            artifact.mkdir(parents=True)
            sentinel = artifact / "live-dump"
            sentinel.write_bytes(b"writer must finish before deletion")
            state_path, paths_path = root / "state.json", root / "paths.txt"
            entry = {
                "source": "database",
                "preparationService": "database-dump",
                "preparationUnit": "nas-v2-database-dump.service",
                "artifactResource": "database-artifact",
                "artifactPath": str(artifact),
            }
            state_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "snapshots": [],
                        "nativeDumps": [entry],
                    }
                ),
                encoding="utf-8",
            )
            paths_path.write_text(str(artifact) + "\n", encoding="utf-8")
            calls = []

            def failing_stop(argv, **kwargs):
                calls.append((argv, kwargs))
                raise runtime.BackupRuntimeError("systemd stop timed out")

            with (
                mock.patch.object(runtime, "BACKUP_STAGING_ROOT", staging),
                mock.patch.object(runtime, "_run", side_effect=failing_stop),
            ):
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "systemd stop timed out"):
                    runtime.cleanup(
                        state_path=state_path,
                        paths_path=paths_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            self.assertEqual(calls, [(["/bin/systemctl", "stop", "nas-v2-database-dump.service"], {})])
            self.assertEqual(sentinel.read_bytes(), b"writer must finish before deletion")
            self.assertEqual(json.loads(state_path.read_text())["nativeDumps"], [entry])
            self.assertTrue(paths_path.exists())

    def test_restic_cleanup_unit_preserves_inherited_stop_deadline(self):
        source = (ROOT / "modules/nas/config/storage-monitoring.nix").read_text(encoding="utf-8")
        unit = source.split("systemd.services.restic-backups-nas-boot-system = ", 1)[1]
        unit = unit.split("systemd.services.nas-backup-authentik-dump", 1)[0]
        self.assertNotIn("TimeoutStopSec", unit)

    def test_native_client_timeouts_retain_pending_work_with_existing_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            inventory_path, paths_path, state_path = root / "inventory.json", root / "paths.txt", root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)))
            calls = []

            def timeout_client(argv, **kwargs):
                calls.append((argv, kwargs["timeout"]))
                pending = json.loads(state_path.read_text())["nativeDumps"]
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0]["artifactPath"], str(artifact))
                if argv[1] == "restart":
                    (artifact / "partial.dump").write_bytes(b"still being written")
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

            with (
                mock.patch.object(runtime, "BACKUP_STAGING_ROOT", staging),
                mock.patch.object(runtime.subprocess, "run", side_effect=timeout_client),
            ):
                with self.assertRaisesRegex(runtime.BackupRuntimeError, "failed to clean.*timed out"):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            self.assertEqual(
                calls,
                [
                    (["/bin/systemctl", "restart", "nas-v2-database-dump.service"], 60),
                    (["/bin/systemctl", "stop", "nas-v2-database-dump.service"], 60),
                ],
            )
            self.assertEqual((artifact / "partial.dump").read_bytes(), b"still being written")
            retained = json.loads(state_path.read_text())
            self.assertEqual(retained["snapshots"], [])
            self.assertEqual(
                retained["nativeDumps"],
                [{"source": "database", **self.inventory(artifact)["resources"][0]["nativeDump"]}],
            )
            self.assertFalse(paths_path.exists())

    def test_cleanup_interruption_during_stop_keeps_exact_pending_obligations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            artifact.mkdir(parents=True)
            sentinel = artifact / "live.dump"
            sentinel.write_bytes(b"unfinished dump")
            entry = {"source": "database", **self.inventory(artifact)["resources"][0]["nativeDump"]}
            state_path, paths_path = root / "state.json", root / "paths.txt"
            state = {"schemaVersion": 1, "snapshots": [], "nativeDumps": [entry]}
            state_path.write_text(json.dumps(state))
            paths_path.write_text(str(artifact) + "\n")
            with (
                mock.patch.object(runtime, "BACKUP_STAGING_ROOT", staging),
                mock.patch.object(runtime, "_run", side_effect=KeyboardInterrupt) as run,
                mock.patch.object(runtime, "_remove_staged_artifact") as remove,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runtime.cleanup(
                        state_path=state_path,
                        paths_path=paths_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
                self.assertEqual(run.call_args.args[0], ["/bin/systemctl", "stop", "nas-v2-database-dump.service"])
                remove.assert_not_called()
            self.assertEqual(json.loads(state_path.read_text()), state)
            self.assertEqual(paths_path.read_text(), str(artifact) + "\n")
            self.assertEqual(sentinel.read_bytes(), b"unfinished dump")

    def test_prepare_interruption_during_restart_keeps_exact_pending_obligations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            inventory_path, paths_path, state_path = root / "inventory.json", root / "paths.txt", root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)))
            entry = {"source": "database", **self.inventory(artifact)["resources"][0]["nativeDump"]}
            state = {"schemaVersion": 1, "snapshots": [], "nativeDumps": [entry]}

            def interrupt_restart(argv):
                self.assertEqual(argv, ["/bin/systemctl", "restart", "nas-v2-database-dump.service"])
                self.assertEqual(json.loads(state_path.read_text()), state)
                (artifact / "partial.dump").write_bytes(b"unfinished dump")
                raise KeyboardInterrupt

            with (
                mock.patch.object(runtime, "BACKUP_STAGING_ROOT", staging),
                mock.patch.object(runtime, "_run", side_effect=interrupt_restart),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runtime.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            self.assertEqual(json.loads(state_path.read_text()), state)
            self.assertEqual((artifact / "partial.dump").read_bytes(), b"unfinished dump")
            self.assertFalse(paths_path.exists())

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

            def fake_run(argv: list[str], **_kwargs) -> str:
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
            runtime._run = lambda _argv, **_kwargs: ""
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
