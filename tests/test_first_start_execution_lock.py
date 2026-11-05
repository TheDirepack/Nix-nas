from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_operation_lock as locks  # noqa: E402
import nas_setup as setup  # noqa: E402


class FirstStartExecutionLockTests(unittest.TestCase):
    def worker(self, root: pathlib.Path, token: str) -> subprocess.CompletedProcess[str]:
        request = root / "request.json"
        password = root / "password.json"
        request.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "jobId": "a" * 24,
                    "reservationToken": token,
                    "config": "/etc/nas-control/setup.json",
                    "planDigest": "c" * 64,
                    "devices": ["/dev/disk/by-id/test-only"],
                    "allowDestructiveStorage": False,
                    "confirmPasswordReapply": False,
                    "encryptStorage": True,
                }
            )
        )
        password.write_text(
            json.dumps(
                {
                    "keepass": "fixture-only-password",
                    "administrator": {
                        "username": "admin",
                        "name": "Administrator",
                        "email": "admin@example.test",
                        "password": "fixture-only-password",
                    },
                }
            )
        )
        request.chmod(0o600)
        password.chmod(0o600)
        environment = {
            **os.environ,
            "NAS_OPERATION_ROOT": str(root / "operations"),
            "NAS_STATE_ALLOW_UNPRIVILEGED": "1",
        }
        environment.pop(locks.COORDINATION_TOKEN_ENV, None)
        code = """
import json,pathlib,sys
sys.path.insert(0,sys.argv[1])
import nas_setup as setup
import nas_operation_lock as locks
root=pathlib.Path(sys.argv[2])
setup.STATE_PATH=root/'state.json'
def mutation_boundary(_args):
    token=locks.current_coordination_token()
    locks.validate_coordination_token(token,setup.SETUP_OPERATION_CLASSES)
    (root/'mutation.json').write_text(json.dumps(locks.operation_state()))
    return {'verifiedExecutionLock':True}
setup._first_run_locked=mutation_boundary
setup.run_root=lambda *_args,**_kwargs:None
setup.run_root_noninteractive=lambda *_args,**_kwargs:type('Result',(),{'returncode':0})()
setup.ensure_secret_gated_services=lambda:None
setup.run_first_start_job(root/'request.json',root/'password.json')
"""
        return subprocess.run(
            [sys.executable, "-c", code, str(ROOT / "services"), str(root)],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def test_real_worker_acquires_the_flock_after_nonbinding_admission(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            operation_root = root / "operations"
            operation_root.mkdir(mode=0o770)
            operation_root.chmod(0o2770)
            with mock.patch.object(locks, "OPERATION_ROOT", operation_root):
                ticket = locks.reserve_operation("first-start-v2", setup.SETUP_OPERATION_CLASSES)
                result = self.worker(root, ticket.token)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                observed = json.loads((root / "mutation.json").read_text())
                self.assertEqual(observed["active"][0]["action"], "first-start-v2")
                self.assertEqual(observed["busyClasses"], sorted(setup.SETUP_OPERATION_CLASSES))
                self.assertEqual(locks.operation_state()["busyClasses"], [])
            job = json.loads((root / "jobs" / ("a" * 24 + ".json")).read_text())
            self.assertEqual(job["status"], "complete")
            self.assertFalse((root / "request.json").exists())
            self.assertFalse((root / "password.json").exists())

    def test_real_worker_fails_closed_if_another_owner_wins_after_admission(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            operation_root = root / "operations"
            operation_root.mkdir(mode=0o770)
            operation_root.chmod(0o2770)
            with mock.patch.object(locks, "OPERATION_ROOT", operation_root):
                ticket = locks.reserve_operation("first-start-v2", setup.SETUP_OPERATION_CLASSES)
                with locks.acquire_operation("competing-operation", ("appliance",)):
                    result = self.worker(root, ticket.token)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Another privileged operation conflicts", result.stderr)
                    self.assertFalse((root / "mutation.json").exists())
                    self.assertEqual(locks.operation_state()["active"][0]["action"], "competing-operation")
            job = json.loads((root / "jobs" / ("a" * 24 + ".json")).read_text())
            self.assertEqual(job["status"], "failed")
            self.assertFalse((root / "request.json").exists())
            self.assertFalse((root / "password.json").exists())


if __name__ == "__main__":
    unittest.main()
