from __future__ import annotations

import datetime as dt
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_backup_v2 as backup  # noqa: E402


class BackupV2Tests(unittest.TestCase):
    def effective(self) -> dict:
        return {
            "storageResources": {
                "projects": {
                    "path": "/tank/projects",
                    "dataset": "tank/projects",
                    "scope": "system",
                    "stateClass": "authoritative",
                    "capabilities": ["read", "write"],
                    "backup": {"enabled": True, "consistency": "zfs-snapshot"},
                },
                "pi-home": {
                    "path": "/tank/apps/pi/users",
                    "scope": "user",
                    "pathTemplate": "/tank/apps/pi/users/{user}",
                    "stateClass": "authoritative",
                    "capabilities": ["read", "write"],
                    "backup": {"enabled": True, "consistency": "filesystem"},
                },
                "auth-db": {
                    "path": "/var/lib/nas-control/apps/authentik",
                    "scope": "system",
                    "stateClass": "authoritative",
                    "capabilities": ["read"],
                    "backup": {"enabled": True, "consistency": "postgres"},
                },
                "cache": {
                    "path": "/tank/cache/models",
                    "scope": "system",
                    "stateClass": "cache",
                    "capabilities": ["read", "write"],
                    "backup": {"enabled": False, "consistency": "none"},
                },
            },
            "backupResources": ["projects", "pi-home", "auth-db"],
        }

    def test_plan_groups_resources_by_consistency(self) -> None:
        timestamp = dt.datetime(2026, 8, 9, 12, 34, 56, tzinfo=dt.timezone.utc)
        plan = backup.build_backup_plan(self.effective(), timestamp=timestamp)
        self.assertEqual(plan["snapshotName"], "nixos-nas-v2-backup-20260809T123456Z")
        self.assertEqual([item["resource"] for item in plan["groups"]["zfs-snapshot"]], ["projects"])
        self.assertEqual([item["resource"] for item in plan["groups"]["filesystem"]], ["pi-home"])
        self.assertEqual([item["resource"] for item in plan["groups"]["postgres"]], ["auth-db"])
        snap = plan["groups"]["zfs-snapshot"][0]
        self.assertEqual(snap["snapshot"], "tank/projects@nixos-nas-v2-backup-20260809T123456Z")
        self.assertEqual(snap["snapshotPath"], "/tank/projects/.zfs/snapshot/nixos-nas-v2-backup-20260809T123456Z")
        self.assertTrue(plan["groups"]["postgres"][0]["requiresNativeStage"])

    def test_dynamic_files_emits_only_requested_consistency_views(self) -> None:
        plan = backup.build_backup_plan(self.effective())
        self.assertEqual(backup.dynamic_files(plan), ["/tank/apps/pi/users"])
        with_snapshots = backup.dynamic_files(plan, include_snapshots=True)
        self.assertIn("/tank/apps/pi/users", with_snapshots)
        self.assertTrue(any("/.zfs/snapshot/" in path for path in with_snapshots))
        self.assertNotIn("/var/lib/nas-control/apps/authentik", with_snapshots)

    @mock.patch.object(backup.subprocess, "run")
    def test_prepare_creates_exact_snapshot_records_state_and_emits_view(self, run) -> None:
        timestamp = dt.datetime(2026, 8, 9, 12, 34, 56, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td, mock.patch.object(pathlib.Path, "is_dir", return_value=True):
            state = pathlib.Path(td) / "state.json"
            files = backup.prepare_files(self.effective(), timestamp=timestamp, state_path=state)
            run.assert_called_once_with(
                ["zfs", "snapshot", "tank/projects@nixos-nas-v2-backup-20260809T123456Z"], check=True
            )
            self.assertIn("/tank/projects/.zfs/snapshot/nixos-nas-v2-backup-20260809T123456Z", files)
            recorded = __import__("json").loads(state.read_text(encoding="utf-8"))
            self.assertEqual(recorded["snapshots"], ["tank/projects@nixos-nas-v2-backup-20260809T123456Z"])

    @mock.patch.object(backup.subprocess, "run")
    def test_cleanup_destroys_only_recorded_exact_snapshot_without_recursive_flags(self, run) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = pathlib.Path(td) / "state.json"
            state.write_text(
                '{"schemaVersion":1,"snapshots":["tank/projects@nixos-nas-v2-backup-20260809T123456Z"]}',
                encoding="utf-8",
            )
            destroyed = backup.cleanup_snapshots(state)
            self.assertEqual(destroyed, ["tank/projects@nixos-nas-v2-backup-20260809T123456Z"])
            run.assert_called_once_with(
                ["zfs", "destroy", "tank/projects@nixos-nas-v2-backup-20260809T123456Z"], check=True
            )
            self.assertFalse(state.exists())
            self.assertNotIn("-r", run.call_args.args[0])
            self.assertNotIn("-R", run.call_args.args[0])

    @mock.patch.object(backup.subprocess, "run")
    def test_prepare_rolls_back_created_snapshot_if_view_is_missing(self, run) -> None:
        timestamp = dt.datetime(2026, 8, 9, 12, 34, 56, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td, mock.patch.object(pathlib.Path, "is_dir", return_value=False):
            state = pathlib.Path(td) / "state.json"
            with self.assertRaisesRegex(backup.BackupPlanError, "filesystem view is unavailable"):
                backup.prepare_files(self.effective(), timestamp=timestamp, state_path=state)
            calls = [call.args[0] for call in run.call_args_list]
            self.assertIn(["zfs", "snapshot", "tank/projects@nixos-nas-v2-backup-20260809T123456Z"], calls)
            self.assertIn(["zfs", "destroy", "tank/projects@nixos-nas-v2-backup-20260809T123456Z"], calls)
            self.assertFalse(state.exists())

    def test_cleanup_refuses_snapshot_outside_owned_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = pathlib.Path(td) / "state.json"
            state.write_text('{"schemaVersion":1,"snapshots":["tank/projects@manual"]}', encoding="utf-8")
            with self.assertRaisesRegex(backup.BackupPlanError, "Refusing to destroy"):
                backup.cleanup_snapshots(state)

    def test_user_scope_preserves_path_template(self) -> None:
        item = backup.build_backup_plan(self.effective())["groups"]["filesystem"][0]
        self.assertEqual(item["pathTemplate"], "/tank/apps/pi/users/{user}")

    def test_zfs_strategy_requires_dataset(self) -> None:
        effective = self.effective()
        del effective["storageResources"]["projects"]["dataset"]
        with self.assertRaisesRegex(backup.BackupPlanError, "requires a valid dataset"):
            backup.build_backup_plan(effective)

    def test_unknown_and_duplicate_inventory_fails_closed(self) -> None:
        effective = self.effective()
        effective["backupResources"] = ["missing"]
        with self.assertRaisesRegex(backup.BackupPlanError, "does not exist"):
            backup.build_backup_plan(effective)
        effective["backupResources"] = ["projects", "projects"]
        with self.assertRaisesRegex(backup.BackupPlanError, "duplicates"):
            backup.build_backup_plan(effective)

    def test_cache_cannot_enter_backup_inventory(self) -> None:
        effective = self.effective()
        effective["backupResources"].append("cache")
        with self.assertRaisesRegex(backup.BackupPlanError, "not enabled for backup"):
            backup.build_backup_plan(effective)

    def test_naive_timestamp_is_normalized_to_utc(self) -> None:
        self.assertEqual(
            backup.snapshot_name(dt.datetime(2026, 8, 9, 1, 2, 3)),
            "nixos-nas-v2-backup-20260809T010203Z",
        )


if __name__ == "__main__":
    unittest.main()
