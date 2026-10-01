from __future__ import annotations

import json
import io
import contextlib
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

    def test_acquire_uses_one_kernel_lock_and_publishes_metadata(self) -> None:
        with locks.acquire_operation("backup", ("storage",)) as operation:
            self.assertEqual(operation.classes, ("storage",))
            self.assertRegex(operation.coordination_token, r"^[0-9a-f]{32}$")
            metadata = json.loads((self.root / locks.LOCK_PATH_NAME).read_text(encoding="utf-8"))
            self.assertEqual(metadata["token"], operation.coordination_token)
            self.assertEqual(metadata["action"], "backup")
            self.assertEqual(metadata["classes"], ["storage"])
            state = locks.operation_state()
            self.assertEqual(state["busyClasses"], ["storage"])
            self.assertEqual(state["reservations"], [])
            self.assertEqual(state["snapshotSemantics"], "advisory-single-kernel-flock")
        self.assertEqual((self.root / locks.LOCK_PATH_NAME).read_text(encoding="utf-8"), "")
        self.assertEqual(locks.operation_state()["busyClasses"], [])

    def test_disjoint_mutation_classes_still_serialize(self) -> None:
        with locks.acquire_operation("backup", ("storage",)):
            token = os.environ.pop(locks.COORDINATION_TOKEN_ENV)
            try:
                with self.assertRaises(locks.OperationBusyError):
                    with locks.acquire_operation("identity", ("identity",)):
                        pass
            finally:
                os.environ[locks.COORDINATION_TOKEN_ENV] = token

    def test_nested_child_validation_uses_live_token_and_class_coverage(self) -> None:
        with locks.acquire_operation("outer", ("identity", "runtime")) as outer:
            token = outer.coordination_token
            locks.validate_coordination_token(token, ("identity",))
            with locks.acquire_operation("nested", ("runtime",)) as nested:
                self.assertEqual(nested.coordination_token, token)
            with self.assertRaisesRegex(locks.OperationBusyError, "does not cover"):
                locks.validate_coordination_token(token, ("storage",))
        with self.assertRaises(locks.OperationBusyError):
            locks.validate_coordination_token(token, ("identity",))

    def test_appliance_class_covers_nested_classes_without_expanding_lock_files(self) -> None:
        with locks.acquire_operation("first-start", ("appliance",)) as operation:
            self.assertEqual(operation.classes, ("appliance",))
            self.assertEqual(locks.operation_state()["busyClasses"], ["appliance"])
            locks.validate_coordination_token(operation.coordination_token, ("storage", "identity"))
        self.assertEqual(sorted(self.root.glob("*.lock")), [self.root / locks.LOCK_PATH_NAME])

    def test_reservation_is_only_an_admission_check(self) -> None:
        reservation = locks.reserve_operation("first-start", ("storage",), ttl_seconds=60)
        self.assertEqual(reservation.classes, ("storage",))
        self.assertRegex(reservation.token, r"^[0-9a-f]{32}$")
        self.assertEqual(sorted(self.root.glob("*.lock")), [self.root / locks.LOCK_PATH_NAME])
        locks.cancel_reservation(reservation.token)

    def test_exception_releases_global_lock(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "boom"):
            with locks.acquire_operation("update", ("update", "runtime")):
                raise RuntimeError("boom")
        self.assertEqual(locks.operation_state()["busyClasses"], [])
        with locks.acquire_operation("after", ("storage",)):
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

    def test_cli_contender_fails_without_executing_command(self) -> None:
        with locks.acquire_operation("backup", ("storage",)):
            token = os.environ.pop(locks.COORDINATION_TOKEN_ENV)
            try:
                with mock.patch("nas_operation_lock.subprocess.run") as run, contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(locks.main(["--action", "update", "--class", "update", "--", "/bin/true"]), 75)
                    run.assert_not_called()
            finally:
                os.environ[locks.COORDINATION_TOKEN_ENV] = token

    def test_cli_rejects_stale_parent_token_for_validation_and_execution(self) -> None:
        with locks.acquire_operation("parent", ("state",)) as parent:
            token = parent.coordination_token
        with mock.patch.dict(os.environ, {locks.COORDINATION_TOKEN_ENV: token}):
            with mock.patch("nas_operation_lock.subprocess.run") as run, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(locks.main(["--class", "state", "--validate-current"]), 76)
                self.assertEqual(locks.main(["--action", "nested", "--class", "state", "--", "/bin/true"]), 76)
                run.assert_not_called()

    def test_different_live_owner_token_is_rejected(self) -> None:
        with locks.acquire_operation("parent", ("state",)):
            with self.assertRaisesRegex(locks.OperationBusyError, "different operation"):
                locks.validate_coordination_token("0" * 32, ("state",))


if __name__ == "__main__":
    unittest.main()
