from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "nas_operation_lock_coverage_test", ROOT / "services" / "nas_operation_lock.py"
)
assert SPEC and SPEC.loader
operation_lock = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = operation_lock
SPEC.loader.exec_module(operation_lock)


class OperationLockCoverageTests(unittest.TestCase):
    def test_json_views_and_empty_class_validation(self) -> None:
        active = operation_lock.ActiveOperation("backup", ("storage",), 42, 100, "boot", "start", "a" * 32)
        self.assertEqual(
            active.as_json(),
            {
                "action": "backup",
                "classes": ["storage"],
                "pid": 42,
                "startedAt": 100,
                "bootId": "boot",
                "processStart": "start",
            },
        )
        reservation = operation_lock.OperationReservation("queued", ("runtime",), "b" * 32, 10, 20, 1000, 2000)
        self.assertEqual(reservation.as_json()["expiresMonotonicNs"], 2000)
        with self.assertRaisesRegex(ValueError, "At least one operation class"):
            operation_lock._normalize_classes(())
        with self.assertRaisesRegex(ValueError, "coordination token"):
            operation_lock._coordination_path("bad")

    def test_ancestor_walk_handles_match_miss_and_parent_failure(self) -> None:
        parents = {30: 20, 20: 10, 10: 1, 1: 0}
        with mock.patch.object(operation_lock, "_parent_pid", side_effect=lambda pid: parents.get(pid)):
            self.assertTrue(operation_lock._is_ancestor_pid(10, current=30))
            self.assertTrue(operation_lock._is_ancestor_pid(30, current=30))
            self.assertFalse(operation_lock._is_ancestor_pid(99, current=30))
        with mock.patch.object(operation_lock, "_parent_pid", return_value=None):
            self.assertFalse(operation_lock._is_ancestor_pid(99, current=30))

    def test_conflicting_reservation_honors_ignore_token(self) -> None:
        first = operation_lock.OperationReservation("one", ("runtime",), "c" * 32, 1, 2, 1, 2)
        second = operation_lock.OperationReservation("two", ("storage",), "d" * 32, 1, 2, 1, 2)
        with mock.patch.object(operation_lock, "_reservations", return_value=[first, second]):
            self.assertIs(operation_lock._conflicting_reservation(("runtime",)), first)
            self.assertIsNone(operation_lock._conflicting_reservation(("runtime",), ignore_token=first.token))
            self.assertIs(
                operation_lock._conflicting_reservation(("storage",), ignore_token=first.token),
                second,
            )


if __name__ == "__main__":
    unittest.main()
