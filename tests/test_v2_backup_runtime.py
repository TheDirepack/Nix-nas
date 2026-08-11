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

import nas_v2_backup_runtime as runtime  # noqa: E402


class V2BackupRuntimeTests(unittest.TestCase):
    def inventory(self, artifact_path: pathlib.Path) -> dict:
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
                        "artifactPath": str(artifact_path),
                    },
                }
            ],
        }

    def test_native_dump_restarts_job_and_publishes_artifact_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact = root / "database-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")
            commands: list[list[str]] = []

            original_run = runtime._run

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

            self.assertEqual(commands, [["/bin/systemctl", "restart", "nas-v2-database-dump.service"]])
            self.assertEqual(paths_path.read_text(encoding="utf-8"), f"{artifact}\n")
            self.assertEqual(result["paths"], [str(artifact)])
            self.assertEqual(result["nativeDumps"][0]["artifactResource"], "database-artifact")
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["nativeDumps"], result["nativeDumps"])

    def test_empty_artifact_after_successful_job_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact = root / "empty-artifact"
            inventory_path = root / "inventory.json"
            paths_path = root / "paths.txt"
            state_path = root / "state.json"
            inventory_path.write_text(json.dumps(self.inventory(artifact)), encoding="utf-8")

            original_run = runtime._run
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

            self.assertTrue(artifact.is_dir())
            self.assertFalse(paths_path.exists())
            self.assertFalse(state_path.exists())

    def test_invalid_native_dump_mapping_never_executes_systemctl(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inventory = self.inventory(root / "artifact")
            del inventory["resources"][0]["nativeDump"]["preparationUnit"]
            inventory_path = root / "inventory.json"
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            called = False
            original_run = runtime._run

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
            self.assertFalse(called)


if __name__ == "__main__":
    unittest.main()
