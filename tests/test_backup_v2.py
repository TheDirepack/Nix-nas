from __future__ import annotations

import datetime as dt
import json
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
        self.assertNotIn("snapshotPath", snap)
        self.assertTrue(plan["groups"]["postgres"][0]["requiresNativeStage"])

    def test_dynamic_files_emits_only_ready_consistency_views(self) -> None:
        plan = backup.build_backup_plan(self.effective())
        self.assertEqual(backup.dynamic_files(plan), ["/tank/apps/pi/users"])
        # A ZFS resource is not emitted until prepare_files has queried the
        # dataset mountpoint, created the snapshot, and verified its view.
        self.assertEqual(backup.dynamic_files(plan, include_snapshots=True), ["/tank/apps/pi/users"])
        self.assertNotIn("/var/lib/nas-control/apps/authentik", backup.dynamic_files(plan, include_snapshots=True))

    @mock.patch.object(backup.subprocess, "run")
    def test_prepare_creates_exact_snapshot_records_state_and_emits_view(self, run) -> None:
        timestamp = dt.datetime(2026, 8, 9, 12, 34, 56, tzinfo=dt.timezone.utc)
        run.side_effect = [mock.Mock(), mock.Mock(stdout="/tank/projects\n")]
        with tempfile.TemporaryDirectory() as td, mock.patch.object(pathlib.Path, "is_dir", return_value=True):
            state = pathlib.Path(td) / "state.json"
            files = backup.prepare_files(self.effective(), timestamp=timestamp, state_path=state)
            self.assertEqual(
                run.call_args_list[0],
                mock.call(["zfs", "snapshot", "tank/projects@nixos-nas-v2-backup-20260809T123456Z"], check=True),
            )
            self.assertEqual(
                run.call_args_list[1],
                mock.call(
                    ["zfs", "get", "-H", "-o", "value", "mountpoint", "tank/projects"],
                    check=True,
                    capture_output=True,
                    text=True,
                ),
            )
            self.assertIn("/tank/projects/.zfs/snapshot/nixos-nas-v2-backup-20260809T123456Z", files)
            recorded = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(recorded["snapshots"], ["tank/projects@nixos-nas-v2-backup-20260809T123456Z"])

    @mock.patch.object(backup.subprocess, "run")
    def test_resource_subdirectory_uses_parent_dataset_snapshot_view(self, run) -> None:
        effective = self.effective()
        effective["storageResources"]["projects"]["path"] = "/tank/shares"
        effective["storageResources"]["projects"]["dataset"] = "tank/nas"
        run.side_effect = [mock.Mock(), mock.Mock(stdout="/tank\n")]
        timestamp = dt.datetime(2026, 8, 9, 12, 34, 56, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td, mock.patch.object(pathlib.Path, "is_dir", return_value=True):
            files = backup.prepare_files(
                effective,
                timestamp=timestamp,
                state_path=pathlib.Path(td) / "state.json",
            )
        self.assertIn("/tank/.zfs/snapshot/nixos-nas-v2-backup-20260809T123456Z/shares", files)

    @mock.patch.object(backup.subprocess, "run")
    def test_multiple_resources_on_one_dataset_create_one_snapshot(self, run) -> None:
        effective = self.effective()
        effective["storageResources"]["media"] = {
            "path": "/tank/projects/media",
            "dataset": "tank/projects",
            "scope": "system",
            "stateClass": "authoritative",
            "capabilities": ["read"],
            "backup": {"enabled": True, "consistency": "zfs-snapshot"},
        }
        effective["backupResources"].append("media")
        run.side_effect = [
            mock.Mock(),
            mock.Mock(stdout="/tank/projects\n"),
            mock.Mock(stdout="/tank/projects\n"),
        ]
        timestamp = dt.datetime(2026, 8, 9, 12, 34, 56, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td, mock.patch.object(pathlib.Path, "is_dir", return_value=True):
            files = backup.prepare_files(
                effective,
                timestamp=timestamp,
                state_path=pathlib.Path(td) / "state.json",
            )
        snapshot_calls = [call for call in run.call_args_list if call.args and call.args[0][:2] == ["zfs", "snapshot"]]
        self.assertEqual(len(snapshot_calls), 1)
        self.assertIn("/tank/projects/.zfs/snapshot/nixos-nas-v2-backup-20260809T123456Z/media", files)

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
        run.side_effect = [mock.Mock(), mock.Mock(stdout="/tank/projects\n"), mock.Mock()]
        with tempfile.TemporaryDirectory() as td, mock.patch.object(pathlib.Path, "is_dir", return_value=False):
            state = pathlib.Path(td) / "state.json"
            with self.assertRaisesRegex(backup.BackupPlanError, "view is unavailable"):
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

    @mock.patch.object(backup.subprocess, "run")
    def test_snapshot_resource_must_be_beneath_dataset_mountpoint(self, run) -> None:
        item = backup.build_backup_plan(self.effective())["groups"]["zfs-snapshot"][0]
        run.return_value = mock.Mock(stdout="/srv/other\n")
        with self.assertRaisesRegex(backup.BackupPlanError, "is not beneath dataset"):
            backup._snapshot_resource_path(item, "nixos-nas-v2-backup-20260809T123456Z")

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
