from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_native_dump as native_dump  # noqa: E402


class V2NativeDumpTests(unittest.TestCase):
    def effective(self) -> dict:
        return {
            "storageResources": {
                "database": {
                    "path": "/var/lib/example-db",
                    "scope": "system",
                    "stateClass": "authoritative",
                    "backup": {"enabled": True, "consistency": "native-dump"},
                },
                "artifact": {
                    "path": "/var/lib/nas-backup-artifacts/example-db",
                    "scope": "system",
                    "stateClass": "derived",
                    "backup": {"enabled": False, "consistency": "filesystem"},
                },
            },
            "services": {
                "database-dump": {
                    "enabled": True,
                    "managed": True,
                    "workload": {"kind": "job", "schedules": []},
                    "storage": [
                        {
                            "resource": "database",
                            "mountPath": "/source",
                            "access": "read",
                        },
                        {
                            "resource": "artifact",
                            "mountPath": "/artifact",
                            "access": "write",
                        },
                    ],
                }
            },
            "derived": {
                "runtime": {
                    "database-dump": {"ownerUnit": "nas-v2-database-dump.service"},
                }
            },
        }

    def test_derives_preparation_unit_and_artifact_without_app_names(self):
        result = native_dump.resolve_native_dump(self.effective(), "database")
        self.assertEqual(
            result,
            {
                "preparationService": "database-dump",
                "preparationUnit": "nas-v2-database-dump.service",
                "artifactResource": "artifact",
                "artifactPath": "/var/lib/nas-backup-artifacts/example-db",
            },
        )

    def test_requires_exactly_one_preparation_job(self):
        effective = self.effective()
        effective["services"]["duplicate"] = dict(effective["services"]["database-dump"])
        effective["derived"]["runtime"]["duplicate"] = {"ownerUnit": "nas-v2-duplicate.service"}
        with self.assertRaisesRegex(native_dump.NativeDumpProjectionError, "exactly one"):
            native_dump.resolve_native_dump(effective, "database")

    def test_non_job_reader_fails_closed(self):
        effective = self.effective()
        effective["services"]["database-dump"]["workload"] = {"kind": "daemon", "activation": "persistent"}
        with self.assertRaisesRegex(native_dump.NativeDumpProjectionError, "not a job"):
            native_dump.resolve_native_dump(effective, "database")

    def test_requires_exactly_one_derived_write_artifact(self):
        effective = self.effective()
        effective["storageResources"]["second"] = {
            "path": "/var/lib/nas-backup-artifacts/second",
            "scope": "system",
            "stateClass": "derived",
            "backup": {"enabled": False, "consistency": "filesystem"},
        }
        effective["services"]["database-dump"]["storage"].append(
            {"resource": "second", "mountPath": "/second", "access": "write"}
        )
        with self.assertRaisesRegex(
            native_dump.NativeDumpProjectionError, "exactly one enabled managed preparation job"
        ):
            native_dump.resolve_native_dump(effective, "database")

    def test_artifact_must_not_be_independently_backed_up(self):
        effective = self.effective()
        effective["storageResources"]["artifact"]["backup"]["enabled"] = True
        with self.assertRaisesRegex(native_dump.NativeDumpProjectionError, "must not be independently backup-enabled"):
            native_dump.resolve_native_dump(effective, "database")

    def test_user_scoped_artifact_fails_closed(self):
        effective = self.effective()
        effective["storageResources"]["artifact"]["scope"] = "user"
        effective["storageResources"]["artifact"]["pathTemplate"] = "/var/lib/nas-backup-artifacts/{user}"
        with self.assertRaisesRegex(native_dump.NativeDumpProjectionError, "system scope"):
            native_dump.resolve_native_dump(effective, "database")


if __name__ == "__main__":
    unittest.main()
