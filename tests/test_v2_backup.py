from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_apply as apply_mod  # noqa: E402
import nas_v2_backup as backup  # noqa: E402


class V2BackupTests(unittest.TestCase):
    def effective(self) -> dict:
        return {
            "schemaVersion": 3,
            "storageResources": {
                "data": {
                    "path": "/tank/data",
                    "dataset": "tank/data",
                    "scope": "system",
                    "stateClass": "authoritative",
                    "backup": {"enabled": True, "consistency": "filesystem"},
                },
                "cache": {
                    "path": "/tank/cache",
                    "scope": "system",
                    "stateClass": "cache",
                    "backup": {"enabled": False, "consistency": "filesystem"},
                },
            },
            "services": {},
            "derived": {"backupResources": ["data"], "runtime": {}},
        }

    def test_compiles_resource_inventory_and_verbatim_path_list(self):
        inventory_bytes, restic_bytes = backup.compile_backup_projection(self.effective())
        inventory = json.loads(inventory_bytes)

        self.assertEqual(inventory["schemaVersion"], 1)
        self.assertEqual(
            inventory["resources"],
            [
                {
                    "consistency": "filesystem",
                    "dataset": "tank/data",
                    "id": "data",
                    "path": "/tank/data",
                    "resticSource": "/tank/data",
                    "scope": "system",
                    "stateClass": "authoritative",
                }
            ],
        )
        self.assertEqual(restic_bytes, b"/tank/data\n")

    def test_projection_is_deterministic_and_sorted_by_path(self):
        effective = self.effective()
        effective["storageResources"]["alpha"] = {
            "path": "/alpha",
            "scope": "system",
            "stateClass": "authoritative",
            "backup": {"enabled": True, "consistency": "none"},
        }
        effective["derived"]["backupResources"] = ["data", "alpha"]

        first = backup.compile_backup_projection(effective)
        second = backup.compile_backup_projection(effective)
        self.assertEqual(first, second)
        self.assertEqual(first[1], b"/alpha\n/tank/data\n")

    def test_zfs_snapshot_stays_in_inventory_for_runtime_preparation(self):
        effective = self.effective()
        effective["storageResources"]["data"]["backup"]["consistency"] = "zfs-snapshot"
        inventory_bytes, restic_bytes = backup.compile_backup_projection(effective)
        entry = json.loads(inventory_bytes)["resources"][0]

        self.assertEqual(entry["consistency"], "zfs-snapshot")
        self.assertEqual(entry["dataset"], "tank/data")
        self.assertIsNone(entry["resticSource"])
        self.assertEqual(restic_bytes, b"")

    def test_native_dump_compiles_preparation_job_and_derived_artifact(self):
        effective = self.effective()
        effective["storageResources"]["data"]["backup"]["consistency"] = "native-dump"
        effective["storageResources"]["dump"] = {
            "path": "/run/backup/data",
            "scope": "system",
            "stateClass": "derived",
            "backup": {"enabled": False, "consistency": "filesystem"},
        }
        effective["services"]["data-dump"] = {
            "enabled": True,
            "managed": True,
            "workload": {"kind": "job", "schedules": []},
            "storage": [
                {"resource": "data", "mountPath": "/source", "access": "read"},
                {"resource": "dump", "mountPath": "/artifact", "access": "write"},
            ],
        }
        effective["derived"]["runtime"]["data-dump"] = {"ownerUnit": "nas-v2-data-dump.service"}

        inventory_bytes, restic_bytes = backup.compile_backup_projection(effective)
        entry = json.loads(inventory_bytes)["resources"][0]
        self.assertEqual(
            entry["nativeDump"],
            {
                "artifactPath": "/run/backup/data",
                "artifactResource": "dump",
                "preparationService": "data-dump",
                "preparationUnit": "nas-v2-data-dump.service",
            },
        )
        self.assertIsNone(entry["resticSource"])
        self.assertEqual(restic_bytes, b"")

    def test_native_dump_without_unique_job_fails_closed(self):
        effective = self.effective()
        effective["storageResources"]["data"]["backup"]["consistency"] = "native-dump"
        with self.assertRaisesRegex(backup.BackupProjectionError, "exactly one enabled managed preparation job"):
            backup.compile_backup_projection(effective)

    def test_duplicate_resolved_paths_fail_closed(self):
        effective = self.effective()
        effective["storageResources"]["other"] = {
            "path": "/tank/data",
            "scope": "system",
            "stateClass": "authoritative",
            "backup": {"enabled": True, "consistency": "filesystem"},
        }
        effective["derived"]["backupResources"].append("other")

        with self.assertRaisesRegex(backup.BackupProjectionError, "same path"):
            backup.compile_backup_projection(effective)

    def test_apply_materializes_backup_files_in_same_transaction(self):
        effective = self.effective()
        plan = {"schemaVersion": 1}
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            paths = apply_mod.ApplyPaths(
                desired=root / "services.yaml",
                schema=root / "schema.json",
                platform=None,
                effective=root / "effective.json",
                plan=root / "plan.json",
            )
            projection = apply_mod.BackupProjection(
                inventory=root / "backup-resources.json",
                restic_paths=root / "backup-paths.txt",
            )

            original_compile_paths_inner = apply_mod._compile_paths_inner
            apply_mod._compile_paths_inner = lambda _paths: (effective, plan)  # type: ignore[method-assign]
            try:
                result = apply_mod.apply(paths, backup=projection)
            finally:
                apply_mod._compile_paths_inner = original_compile_paths_inner  # type: ignore[method-assign]

            self.assertEqual((root / "backup-paths.txt").read_text(encoding="utf-8"), "/tank/data\n")
            inventory = json.loads((root / "backup-resources.json").read_text(encoding="utf-8"))
            self.assertEqual(inventory["resources"][0]["id"], "data")
            self.assertIn(str(root / "backup-resources.json"), result["changedFiles"])
            self.assertIn(str(root / "backup-paths.txt"), result["changedFiles"])

    def test_nix_keeps_restic_native_and_preparation_application_agnostic(self):
        default_module = (ROOT / "modules/nas/default.nix").read_text(encoding="utf-8")
        storage = (ROOT / "modules/nas/config/storage-monitoring.nix").read_text(encoding="utf-8")
        operations = (ROOT / "modules/nas/config/managed-services-operations.nix").read_text(encoding="utf-8")
        resources = (ROOT / "modules/nas/config/managed-services-backup-resources.nix").read_text(encoding="utf-8")

        self.assertIn("./config/managed-services-backup-resources.nix", default_module)
        self.assertIn("services.restic.backups", storage)
        self.assertIn("dynamicFilesFrom", storage)
        self.assertIn("nas_v2_backup_runtime.py prepare", storage)
        self.assertIn("--systemctl ${pkgs.systemd}/bin/systemctl", storage)
        self.assertNotIn("pg_dump --format=custom authentik", storage)
        self.assertNotIn("PYSQLITEBACKUP", storage)
        self.assertNotIn("systemctl start backup-vaultwarden.service", storage)
        self.assertIn('job "restic-backups-nas-boot-system.service"', operations)
        self.assertIn("nas-boot-system.timerConfig = lib.mkForce null", operations)
        self.assertIn('consistency = "native-dump";', resources)
        self.assertIn('unit = "backup-vaultwarden.service";', resources)
        self.assertNotIn("restic backup", operations)


if __name__ == "__main__":
    unittest.main()
