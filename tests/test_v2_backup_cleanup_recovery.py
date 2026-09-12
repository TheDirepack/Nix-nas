from __future__ import annotations

import json
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_backup as backup  # noqa: E402


def _native_inventory(artifact: pathlib.Path) -> dict:
    return {
        "schemaVersion": 1,
        "resources": [
            {
                "id": "database",
                "path": "/var/lib/example-db",
                "consistency": "native-dump",
                "nativeDump": {
                    "preparationService": "database-dump",
                    "preparationUnit": "nas-v2-database-dump.service",
                    "artifactResource": "database-artifact",
                    "artifactPath": str(artifact),
                },
            }
        ],
    }


class Ws03CleanupRecoveryTests(unittest.TestCase):
    def test_second_prepare_preserves_retained_cleanup_obligations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            artifact.mkdir(parents=True)
            residue = artifact / "partial.dump"
            residue.write_bytes(b"retained-sensitive-bytes")
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(_native_inventory(artifact)), encoding="utf-8")
            retained_state = {
                "schemaVersion": 1,
                "snapshots": [{"dataset": "tank/data", "name": "retained-snapshot"}],
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
            state_path.write_text(json.dumps(retained_state), encoding="utf-8")
            paths_path.write_text("retained-runtime-path\n", encoding="utf-8")
            original_run = backup._run
            original_root = backup.BACKUP_STAGING_ROOT
            backup.BACKUP_STAGING_ROOT = staging

            def unexpected_run(argv: list[str]) -> str:
                raise AssertionError(f"prepare must require cleanup before native work: {argv}")

            backup._run = unexpected_run
            try:
                with self.assertRaisesRegex(backup.BackupRuntimeError, "cleanup.*required|required.*cleanup"):
                    backup.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                backup._run = original_run
                backup.BACKUP_STAGING_ROOT = original_root
            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), retained_state)
            self.assertEqual(residue.read_bytes(), b"retained-sensitive-bytes")
            self.assertEqual(paths_path.read_text(encoding="utf-8"), "retained-runtime-path\n")

    def test_partial_dump_failure_publishes_nothing_and_removes_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(_native_inventory(artifact)), encoding="utf-8")
            original_run = backup._run
            original_root = backup.BACKUP_STAGING_ROOT
            backup.BACKUP_STAGING_ROOT = staging

            def fake_run(argv: list[str]) -> str:
                if argv == ["/bin/systemctl", "restart", "nas-v2-database-dump.service"]:
                    artifact.mkdir(parents=True, exist_ok=True)
                    (artifact / "partial.dump").write_bytes(b"partial-sensitive-bytes")
                    raise backup.BackupRuntimeError("preparation unit failed")
                raise AssertionError(f"unexpected command: {argv}")

            backup._run = fake_run
            try:
                with self.assertRaises(backup.BackupRuntimeError):
                    backup.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                backup._run = original_run
                backup.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(paths_path.exists())
            self.assertFalse(state_path.exists())
            self.assertFalse((artifact / "partial.dump").exists())
            # Stale/partial output must not linger anywhere under staging.
            leftovers = [p for p in staging.rglob("*") if p.is_file()] if staging.exists() else []
            self.assertEqual(leftovers, [])

    def test_partial_dump_removal_failure_retains_exact_obligation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(_native_inventory(artifact)), encoding="utf-8")
            original_run = backup._run
            original_root = backup.BACKUP_STAGING_ROOT
            original_remove = backup._remove_staged_artifact
            backup.BACKUP_STAGING_ROOT = staging

            def fake_run(argv: list[str]) -> str:
                if argv == ["/bin/systemctl", "restart", "nas-v2-database-dump.service"]:
                    artifact.mkdir(parents=True, exist_ok=True)
                    (artifact / "partial.dump").write_bytes(b"partial-sensitive-bytes")
                    raise backup.BackupRuntimeError("preparation unit failed")
                raise AssertionError(f"unexpected command: {argv}")

            def failing_remove(_path: str) -> None:
                raise backup.BackupRuntimeError("removal failed: permission denied")

            backup._run = fake_run
            backup._remove_staged_artifact = failing_remove  # type: ignore[assignment]
            try:
                with self.assertRaisesRegex(backup.BackupRuntimeError, "failed to clean"):
                    backup.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                backup._run = original_run
                backup._remove_staged_artifact = original_remove  # type: ignore[assignment]
                backup.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(paths_path.exists())
            self.assertTrue(state_path.exists())
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(len(state["nativeDumps"]), 1)
            retained = state["nativeDumps"][0]["artifactPath"]
            self.assertEqual(retained, str(artifact))
            self.assertTrue(str(retained).startswith(str(staging)))

    def test_mixed_cleanup_retains_only_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state_path = root / "state.json"
            paths_path = root / "paths.txt"
            state_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "snapshots": [
                            {"dataset": "tank/a", "name": "snap-good"},
                            {"dataset": "tank/b", "name": "snap-bad"},
                        ],
                        "nativeDumps": [],
                    }
                ),
                encoding="utf-8",
            )
            paths_path.write_text("placeholder\n", encoding="utf-8")
            original_run = backup._run
            calls: list[list[str]] = []

            def fake_run(argv: list[str]) -> str:
                calls.append(argv)
                if argv == ["/bin/zfs", "destroy", "tank/b@snap-bad"]:
                    raise backup.BackupRuntimeError("destroy failed")
                if argv == ["/bin/zfs", "destroy", "tank/a@snap-good"]:
                    return ""
                if argv[:2] == ["/bin/zfs", "list"]:
                    # Both snapshots still exist natively; the bad destroy is real.
                    return str(argv[-1])
                raise AssertionError(f"unexpected command: {argv}")

            backup._run = fake_run
            try:
                with self.assertRaisesRegex(backup.BackupRuntimeError, "failed to clean"):
                    backup.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            finally:
                backup._run = original_run
            self.assertTrue(state_path.exists())
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["snapshots"], [{"dataset": "tank/b", "name": "snap-bad"}])
            self.assertEqual(state["nativeDumps"], [])

    def test_already_absent_snapshot_counts_as_complete_after_absence_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state_path = root / "state.json"
            paths_path = root / "paths.txt"
            state_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "snapshots": [{"dataset": "tank/a", "name": "snap-gone"}],
                        "nativeDumps": [],
                    }
                ),
                encoding="utf-8",
            )
            paths_path.write_text("placeholder\n", encoding="utf-8")
            original_run = backup._run
            absence_probed: list[list[str]] = []

            def fake_run(argv: list[str]) -> str:
                if argv == ["/bin/zfs", "destroy", "tank/a@snap-gone"]:
                    raise backup.BackupRuntimeError("dataset does not exist")
                if argv[:3] == ["/bin/zfs", "list", "tank/a@snap-gone"] or (
                    len(argv) >= 2 and argv[0] == "/bin/zfs" and argv[1] == "list"
                ):
                    absence_probed.append(argv)
                    raise backup.BackupRuntimeError("dataset does not exist")
                raise AssertionError(f"unexpected command: {argv}")

            backup._run = fake_run
            try:
                result = backup.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            finally:
                backup._run = original_run
            self.assertTrue(absence_probed, "cleanup must verify native absence before treating as complete")
            self.assertFalse(state_path.exists())
            self.assertFalse(paths_path.exists())
            self.assertEqual(result["destroyed"], ["tank/a@snap-gone"])

    def test_cleanup_retry_does_not_repeat_completed_destroys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state_path = root / "state.json"
            paths_path = root / "paths.txt"
            state_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "snapshots": [
                            {"dataset": "tank/a", "name": "snap-a"},
                            {"dataset": "tank/b", "name": "snap-b"},
                        ],
                        "nativeDumps": [],
                    }
                ),
                encoding="utf-8",
            )
            paths_path.write_text("placeholder\n", encoding="utf-8")
            original_run = backup._run
            destroys: list[str] = []
            attempt = {"count": 0}

            def fake_run(argv: list[str]) -> str:
                if len(argv) >= 2 and argv[0] == "/bin/zfs" and argv[1] == "destroy":
                    destroys.append(argv[2])
                    if argv[2] == "tank/a@snap-a":
                        return ""
                    if attempt["count"] == 0:
                        raise backup.BackupRuntimeError("transient destroy failure")
                    return ""
                if len(argv) >= 2 and argv[0] == "/bin/zfs" and argv[1] == "list":
                    # snap-b still exists on first attempt, so the failure is real.
                    return str(argv[-1])
                raise AssertionError(f"unexpected command: {argv}")

            backup._run = fake_run
            try:
                with self.assertRaises(backup.BackupRuntimeError):
                    backup.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
                attempt["count"] += 1
                destroys.clear()
                result = backup.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            finally:
                backup._run = original_run
            self.assertEqual(destroys, ["tank/b@snap-b"])
            self.assertFalse(state_path.exists())
            self.assertIn("tank/b@snap-b", result["destroyed"])
            self.assertNotIn("tank/a@snap-a", result["destroyed"])

    def test_interruption_between_state_updates_remains_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            state_path = root / "state.json"
            paths_path = root / "paths.txt"
            state_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "snapshots": [
                            {"dataset": "tank/a", "name": "snap-a"},
                            {"dataset": "tank/b", "name": "snap-b"},
                        ],
                        "nativeDumps": [],
                    }
                ),
                encoding="utf-8",
            )
            paths_path.write_text("placeholder\n", encoding="utf-8")
            original_run = backup._run
            destroys: list[str] = []

            def fake_run(argv: list[str]) -> str:
                if len(argv) >= 2 and argv[0] == "/bin/zfs" and argv[1] == "destroy":
                    destroys.append(argv[2])
                    if argv[2] == "tank/b@snap-b":
                        return ""
                    raise OSError("simulated host crash mid-cleanup")
                if len(argv) >= 2 and argv[0] == "/bin/zfs" and argv[1] == "list":
                    return str(argv[-1])
                raise AssertionError(f"unexpected command: {argv}")

            backup._run = fake_run
            try:
                # Reverse order cleans snap-b first, persists, then the crash
                # propagates without losing the completed step.
                with self.assertRaises(OSError):
                    backup.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            finally:
                backup._run = original_run
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["snapshots"], [{"dataset": "tank/a", "name": "snap-a"}])

            def recovery_run(argv: list[str]) -> str:
                if len(argv) >= 2 and argv[0] == "/bin/zfs" and argv[1] == "destroy":
                    destroys.append(argv[2])
                    return ""
                raise AssertionError(f"unexpected command: {argv}")

            backup._run = recovery_run
            try:
                result = backup.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin="/bin/zfs")
            finally:
                backup._run = original_run
            self.assertEqual(destroys.count("tank/b@snap-b"), 1)
            self.assertEqual(result["destroyed"], ["tank/a@snap-a"])
            self.assertFalse(state_path.exists())

    def test_prepare_failure_cleanup_checkpoints_each_completed_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "resources": [
                            {"id": "a", "path": "/tank/a", "dataset": "tank/a", "consistency": "zfs-snapshot"},
                            {"id": "b", "path": "/tank/b", "dataset": "tank/b", "consistency": "zfs-snapshot"},
                            {"id": "c", "path": "/tank/c", "dataset": "tank/c", "consistency": "zfs-snapshot"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            original_run = backup._run
            snapshots: list[str] = []

            def fake_run(argv: list[str]) -> str:
                if argv[:2] == ["/bin/zfs", "get"]:
                    dataset = argv[-1]
                    if dataset == "tank/c":
                        raise backup.BackupRuntimeError("trigger preparation failure")
                    return f"/{dataset}"
                if argv[:2] == ["/bin/zfs", "snapshot"]:
                    snapshots.append(argv[2])
                    return ""
                if argv[:2] == ["/bin/zfs", "destroy"]:
                    if argv[2].startswith("tank/b@"):
                        snapshots.remove(argv[2])
                        return ""
                    raise OSError("simulated interruption during preparation-failure cleanup")
                raise AssertionError(f"unexpected command: {argv}")

            backup._run = fake_run
            try:
                with self.assertRaisesRegex(OSError, "simulated interruption"):
                    backup.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin="/bin/zfs",
                        systemctl_bin="/bin/systemctl",
                    )
            finally:
                backup._run = original_run
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(len(state["snapshots"]), 1)
            self.assertEqual(state["snapshots"][0]["dataset"], "tank/a")
            self.assertEqual(snapshots, [f"tank/a@{state['snapshots'][0]['name']}"])
            self.assertFalse(paths_path.exists())

    def test_native_subprocess_fixture_partial_dump_is_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            bin_dir = root / "bin"
            bin_dir.mkdir()
            zfs_fake = bin_dir / "zfs"
            zfs_fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            zfs_fake.chmod(0o755)
            ctl_fake = bin_dir / "systemctl"
            ctl_fake.write_text(
                "#!/bin/sh\n"
                f"mkdir -p {artifact}\n"
                f"printf 'partial' > {artifact}/partial.dump\n"
                "echo 'simulated preparation failure' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            ctl_fake.chmod(0o755)
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(_native_inventory(artifact)), encoding="utf-8")
            original_root = backup.BACKUP_STAGING_ROOT
            backup.BACKUP_STAGING_ROOT = staging
            try:
                with self.assertRaises(backup.BackupRuntimeError):
                    backup.prepare(
                        inventory_path=inventory_path,
                        paths_path=paths_path,
                        state_path=state_path,
                        zfs_bin=str(zfs_fake),
                        systemctl_bin=str(ctl_fake),
                    )
            finally:
                backup.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(paths_path.exists())
            leftovers = [p for p in staging.rglob("*") if p.is_file()] if staging.exists() else []
            self.assertEqual(leftovers, [])

    def test_native_sqlite_dump_roundtrip_through_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            staging = root / "backup-staging"
            artifact = staging / "database-artifact"
            bin_dir = root / "bin"
            bin_dir.mkdir()
            source_db = root / "source.db"
            with sqlite3.connect(source_db) as handle:
                handle.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, value TEXT)")
                handle.execute("INSERT INTO t (value) VALUES ('hello')")
            zfs_fake = bin_dir / "zfs"
            zfs_fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            zfs_fake.chmod(0o755)
            ctl_fake = bin_dir / "systemctl"
            ctl_fake.write_text(
                "#!/bin/sh\n"
                f"mkdir -p {artifact}\n"
                f"{sys.executable} - {source_db} {artifact}/backup.db <<'PY'\n"
                "import pathlib, sqlite3, sys\n"
                "source = pathlib.Path(sys.argv[1])\n"
                "destination = pathlib.Path(sys.argv[2])\n"
                "with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as src:\n"
                "    with sqlite3.connect(destination) as dst:\n"
                "        src.backup(dst)\n"
                "PY\n",
                encoding="utf-8",
            )
            ctl_fake.chmod(0o755)
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(_native_inventory(artifact)), encoding="utf-8")
            original_root = backup.BACKUP_STAGING_ROOT
            backup.BACKUP_STAGING_ROOT = staging
            original_run_impl = backup._run

            def native_run(argv: list[str], timeout: int = 60) -> str:
                result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
                if result.returncode != 0:
                    detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
                    raise backup.BackupRuntimeError(f"native backup command failed: {detail}")
                return result.stdout.strip()

            backup._run = native_run  # type: ignore[assignment]
            try:
                result = backup.prepare(
                    inventory_path=inventory_path,
                    paths_path=paths_path,
                    state_path=state_path,
                    zfs_bin=str(zfs_fake),
                    systemctl_bin=str(ctl_fake),
                )
                self.assertEqual(result["paths"], [str(artifact)])
                dumped = artifact / "backup.db"
                self.assertTrue(dumped.is_file())
                with sqlite3.connect(f"file:{dumped}?mode=ro", uri=True) as handle:
                    rows = handle.execute("SELECT value FROM t").fetchall()
                self.assertEqual(rows, [("hello",)])
                cleanup_result = backup.cleanup(state_path=state_path, paths_path=paths_path, zfs_bin=str(zfs_fake))
                self.assertEqual(cleanup_result["destroyed"], [])
            finally:
                backup._run = original_run_impl  # type: ignore[assignment]
                backup.BACKUP_STAGING_ROOT = original_root
            self.assertFalse(state_path.exists())
            self.assertFalse((artifact / "backup.db").exists())


if __name__ == "__main__":
    unittest.main()
