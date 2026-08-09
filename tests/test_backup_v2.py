from __future__ import annotations

import datetime as dt
import pathlib
import sys
import unittest

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
        self.assertEqual(
            plan["groups"]["zfs-snapshot"][0]["snapshot"],
            "tank/projects@nixos-nas-v2-backup-20260809T123456Z",
        )
        self.assertTrue(plan["groups"]["postgres"][0]["requiresNativeStage"])

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
