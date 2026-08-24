from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_operation_lock as locks  # noqa: E402


class OperationLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name) / "operations"
        self.env = mock.patch.dict(os.environ, {"NAS_STATE_ALLOW_UNPRIVILEGED": "1"}, clear=False)
        self.env.start()
        self.root_patch = mock.patch.object(locks, "OPERATION_ROOT", self.root)
        self.root_patch.start()
        os.environ.pop(locks.COORDINATION_TOKEN_ENV, None)

    def tearDown(self) -> None:
        os.environ.pop(locks.COORDINATION_TOKEN_ENV, None)
        self.root_patch.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_acquire_holds_kernel_lock_and_publishes_minimal_metadata(self) -> None:
        with locks.acquire_operation("backup", ("storage",)) as operation:
            self.assertEqual(operation.classes, ("storage",))
            self.assertRegex(operation.coordination_token, r"^[0-9a-f]{32}$")
            metadata = json.loads((self.root / "storage.lock").read_text(encoding="utf-8"))
            self.assertEqual(metadata["token"], operation.coordination_token)
            self.assertEqual(metadata["action"], "backup")
            state = locks.operation_state()
            self.assertEqual(state["busyClasses"], ["storage"])
            self.assertEqual(state["reservations"], [])
            self.assertEqual(state["snapshotSemantics"], "advisory-kernel-flock")
        self.assertEqual((self.root / "storage.lock").read_text(encoding="utf-8"), "")
        self.assertEqual(locks.operation_state()["busyClasses"], [])

    def test_nested_child_validation_uses_live_token_not_proc_ancestry(self) -> None:
        with locks.acquire_operation("outer", ("identity", "runtime")) as outer:
            token = outer.coordination_token
            locks.validate_coordination_token(token, ("identity",))
            with locks.acquire_operation("nested", ("runtime",)) as nested:
                self.assertEqual(nested.coordination_token, token)
            with self.assertRaisesRegex(locks.OperationBusyError, "no longer owns"):
                locks.validate_coordination_token(token, ("storage",))
        with self.assertRaises(locks.OperationBusyError):
            locks.validate_coordination_token(token, ("identity",))

    def test_appliance_class_expands_to_every_conflict_class(self) -> None:
        with locks.acquire_operation("first-start", ("appliance",)) as operation:
            self.assertEqual(operation.classes, tuple(sorted(locks.KNOWN_CLASSES)))
            self.assertEqual(locks.operation_state()["busyClasses"], list(sorted(locks.KNOWN_CLASSES)))

    def test_reservation_is_only_admission_hint_and_creates_no_database(self) -> None:
        reservation = locks.reserve_operation("first-start", ("storage",), ttl_seconds=60)
        self.assertEqual(reservation.classes, ("storage",))
        self.assertRegex(reservation.token, r"^[0-9a-f]{32}$")
        self.assertFalse(list(self.root.glob("reservation-*.json")))
        locks.cancel_reservation(reservation.token)

    def test_reservation_refuses_currently_busy_class(self) -> None:
        # Remove the inherited coordination token to model an independent
        # asynchronous launcher checking admission while a worker owns storage.
        with locks.acquire_operation("backup", ("storage",)):
            token = os.environ.pop(locks.COORDINATION_TOKEN_ENV)
            try:
                with self.assertRaisesRegex(locks.OperationBusyError, "storage"):
                    locks.reserve_operation("other", ("storage",), ttl_seconds=60)
            finally:
                os.environ[locks.COORDINATION_TOKEN_ENV] = token

    def test_exception_releases_all_class_locks(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "boom"):
            with locks.acquire_operation("update", ("update", "runtime")):
                raise RuntimeError("boom")
        self.assertEqual(locks.operation_state()["busyClasses"], [])
        with locks.acquire_operation("after", ("update", "runtime")):
            pass

    def test_unknown_class_and_bad_token_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            with locks.acquire_operation("bad", ("not-a-class",)):
                pass
        with self.assertRaisesRegex(locks.OperationBusyError, "malformed"):
            locks.validate_coordination_token("../../bad", ("storage",))
        with self.assertRaises(ValueError):
            locks.cancel_reservation("bad")

    def test_cli_nested_validation_and_command_execution(self) -> None:
        with locks.acquire_operation("outer", ("state",)):
            self.assertEqual(locks.main(["--class", "state", "--validate-current"]), 0)
            with mock.patch("nas_operation_lock.subprocess.run") as run:
                run.return_value.returncode = 7
                result = locks.main(["--action", "nested", "--class", "state", "--", "/bin/false"])
                self.assertEqual(result, 7)
                run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
