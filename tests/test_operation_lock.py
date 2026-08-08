from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nas_operation_lock_test", ROOT / "services" / "nas_operation_lock.py")
assert SPEC and SPEC.loader
operation_lock = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = operation_lock
SPEC.loader.exec_module(operation_lock)


class OperationLockTests(unittest.TestCase):
    def test_conflicting_operations_publish_and_clear_runtime_state(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            with operation_lock.acquire_operation("scrub", ("storage",)):
                state = operation_lock.operation_state()
                self.assertIn("storage", state["busyClasses"])
                self.assertEqual("scrub", state["active"][0]["action"])
                with self.assertRaisesRegex(operation_lock.OperationBusyError, "storage"):
                    with operation_lock.acquire_operation("backup", ("storage",)):
                        self.fail("conflicting operation unexpectedly acquired the lock")
            state = operation_lock.operation_state()
            self.assertNotIn("storage", state["busyClasses"])
            self.assertEqual([], state["active"])

    def test_lock_classes_are_sorted_and_unknown_classes_fail_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            with operation_lock.acquire_operation("setup", ("storage", "identity", "storage")) as active:
                self.assertEqual(("identity", "storage"), active.classes)
            with self.assertRaisesRegex(ValueError, "Unknown appliance operation class"):
                with operation_lock.acquire_operation("unsafe", ("arbitrary",)):
                    self.fail("unknown operation class unexpectedly acquired a lock")

    def test_async_reservation_blocks_competitors_and_is_atomically_claimed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            reservation = operation_lock.reserve_operation("first-start", ("appliance", "storage"), ttl_seconds=60)
            state = operation_lock.operation_state()
            self.assertIn("storage", state["busyClasses"])
            self.assertEqual(reservation.token, state["reservations"][0]["token"])
            with self.assertRaisesRegex(operation_lock.OperationBusyError, "storage"):
                with operation_lock.acquire_operation("restore", ("storage",)):
                    self.fail("a reserved class was acquired by a competing operation")
            with operation_lock.acquire_operation(
                "first-start",
                ("storage", "appliance"),
                reservation_token=reservation.token,
            ):
                claimed = operation_lock.operation_state()
                self.assertEqual([], claimed["reservations"])
                self.assertIn("appliance", claimed["busyClasses"])
            self.assertEqual([], operation_lock.operation_state()["busyClasses"])

    def test_cancel_and_expiry_remove_async_reservations(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            reservation = operation_lock.reserve_operation("queued", ("runtime",), ttl_seconds=30)
            operation_lock.cancel_reservation(reservation.token)
            self.assertEqual([], operation_lock.operation_state()["reservations"])
            reservation = operation_lock.reserve_operation("queued", ("runtime",), ttl_seconds=30)
            path = pathlib.Path(temporary) / f"reservation-{reservation.token}.json"
            value = __import__("json").loads(path.read_text())
            value["expiresMonotonicNs"] = value["createdMonotonicNs"] - 1
            path.write_text(__import__("json").dumps(value))
            self.assertEqual([], operation_lock.operation_state()["reservations"])
            self.assertFalse(path.exists())

    def test_reservation_expiry_uses_monotonic_clock_not_wall_clock(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            reservation = operation_lock.reserve_operation("queued", ("runtime",), ttl_seconds=30)
            with mock.patch.object(operation_lock.time, "time", return_value=0):
                active = operation_lock.operation_state()["reservations"]
            self.assertEqual(active[0]["token"], reservation.token)
            self.assertIn("expiresMonotonicNs", active[0])

    def test_appliance_is_globally_exclusive_against_every_mutation_class(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            with operation_lock.acquire_operation("identity-sync", ("identity",)):
                with self.assertRaises(operation_lock.OperationBusyError):
                    with operation_lock.acquire_operation("restore", ("appliance",)):
                        self.fail("appliance lock must conflict with an existing identity mutation")
            with operation_lock.acquire_operation("restore", ("appliance",)) as active:
                self.assertEqual(set(active.classes), set(operation_lock.KNOWN_CLASSES))
                with self.assertRaises(operation_lock.OperationBusyError):
                    with operation_lock.acquire_operation("network-change", ("network",)):
                        self.fail("ordinary mutations must conflict with the appliance wildcard")

    def test_existing_operation_root_is_verified_not_chmodded(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
            mock.patch.object(operation_lock.os, "chmod") as chmod,
        ):
            operation_lock.ensure_root()
        chmod.assert_not_called()

    @unittest.skipIf(os.geteuid() != 0, "requires root-owned operation root (VM with systemd-tmpfiles)")
    def test_missing_operation_root_fallback_restores_group_and_setgid_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "operations"
            group = mock.Mock(gr_gid=os.getgid())
            with (
                mock.patch.object(operation_lock, "OPERATION_ROOT", root),
                mock.patch.object(operation_lock.grp, "getgrnam", return_value=group),
            ):
                operation_lock.ensure_root()
                self.assertEqual(root.stat().st_uid, 0)
                self.assertEqual(root.stat().st_gid, os.getgid())
                self.assertEqual(root.stat().st_mode & 0o7777, 0o2770)

    def test_operation_runner_holds_requested_classes_and_marks_child_coordinated(self) -> None:
        active = operation_lock.ActiveOperation("update", ("update",), 1, 1, "boot", "start", "a" * 32)
        context = mock.MagicMock()
        context.__enter__.return_value = active
        completed = operation_lock.subprocess.CompletedProcess(["true"], 7)
        with (
            mock.patch.object(operation_lock, "acquire_operation", return_value=context) as acquire,
            mock.patch.object(operation_lock.subprocess, "run", return_value=completed) as run,
            mock.patch.dict(operation_lock.os.environ, {}, clear=True),
        ):
            self.assertEqual(
                operation_lock.main(["--action", "update", "--class", "update", "--", "example", "arg"]),
                7,
            )
        acquire.assert_called_once_with("update", ["update"])
        self.assertEqual(run.call_args.args[0], ["example", "arg"])
        self.assertEqual(
            run.call_args.kwargs["env"][operation_lock.COORDINATION_TOKEN_ENV],
            "a" * 32,
        )
        self.assertFalse(run.call_args.kwargs["check"])

    @unittest.skipIf(
        os.geteuid() != 0 or not pathlib.Path("/proc/self/status").exists(),
        "requires VM /proc and systemd-tmpfiles operation root (host hermetic cannot emulate live ancestor PID)",
    )
    def test_operation_runner_validates_live_ancestor_token_without_self_deadlock(self) -> None:
        completed = operation_lock.subprocess.CompletedProcess(["true"], 0)
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            with operation_lock.acquire_operation("parent", ("runtime",)) as parent:
                with (
                    mock.patch.object(operation_lock, "acquire_operation") as acquire,
                    mock.patch.object(operation_lock.subprocess, "run", return_value=completed),
                    mock.patch.dict(
                        operation_lock.os.environ,
                        {operation_lock.COORDINATION_TOKEN_ENV: parent.coordination_token},
                        clear=True,
                    ),
                ):
                    self.assertEqual(
                        operation_lock.main(["--action", "child", "--class", "runtime", "--", "example"]),
                        0,
                    )
                acquire.assert_not_called()

    def test_legacy_boolean_environment_cannot_bypass_operation_lock(self) -> None:
        active = operation_lock.ActiveOperation("child", ("runtime",), 1, 1, "boot", "start", "b" * 32)
        context = mock.MagicMock()
        context.__enter__.return_value = active
        completed = operation_lock.subprocess.CompletedProcess(["true"], 0)
        with (
            mock.patch.object(operation_lock, "acquire_operation", return_value=context) as acquire,
            mock.patch.object(operation_lock.subprocess, "run", return_value=completed),
            mock.patch.dict(operation_lock.os.environ, {"NAS_OPERATION_COORDINATED": "1"}, clear=True),
        ):
            self.assertEqual(
                operation_lock.main(["--action", "child", "--class", "runtime", "--", "example"]),
                0,
            )
        acquire.assert_called_once_with("child", ["runtime"])

    def test_invalid_coordination_token_fails_closed(self) -> None:
        with (
            mock.patch.dict(
                operation_lock.os.environ,
                {operation_lock.COORDINATION_TOKEN_ENV: "0" * 32},
                clear=True,
            ),
            mock.patch.object(operation_lock, "acquire_operation") as acquire,
        ):
            self.assertEqual(
                operation_lock.main(["--action", "child", "--class", "runtime", "--", "example"]),
                76,
            )
        acquire.assert_not_called()

    def test_validate_current_requires_a_live_parent_token(self) -> None:
        with mock.patch.dict(operation_lock.os.environ, {}, clear=True):
            self.assertEqual(
                operation_lock.main(["--class", "runtime", "--validate-current"]),
                76,
            )

    def test_current_coordination_token_exists_only_while_lock_is_held(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            with self.assertRaisesRegex(RuntimeError, "No active"):
                operation_lock.current_coordination_token()
            with operation_lock.acquire_operation("parent", ("identity",)) as active:
                self.assertEqual(operation_lock.current_coordination_token(), active.coordination_token)
            with self.assertRaisesRegex(RuntimeError, "No active"):
                operation_lock.current_coordination_token()

    def test_parent_token_rejects_unrelated_physical_lock_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)
        ):
            with operation_lock.acquire_operation("parent", ("identity",)) as active:
                with mock.patch.object(operation_lock, "_lock_owner_pid", return_value=os.getpid() + 1000):
                    with self.assertRaises(operation_lock.OperationBusyError):
                        operation_lock.validate_coordination_token(active.coordination_token, ("identity",))

    def test_parent_token_cannot_claim_classes_the_parent_does_not_hold(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            with operation_lock.acquire_operation("parent", ("runtime",)) as active:
                with self.assertRaisesRegex(operation_lock.OperationBusyError, "not valid"):
                    operation_lock.validate_coordination_token(active.coordination_token, ("identity",))

    def test_coordination_claim_rejects_bad_fields_and_untrusted_mode(self) -> None:
        import json

        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            token = "c" * 32
            path = pathlib.Path(temporary) / f"coordination-{token}.json"
            path.write_text(json.dumps({"wrong": True}), encoding="utf-8")
            path.chmod(0o640)
            with self.assertRaisesRegex(operation_lock.OperationBusyError, "invalid fields"):
                operation_lock.validate_coordination_token(token, ("runtime",))

            path.write_text("{}", encoding="utf-8")
            path.chmod(0o646)
            with self.assertRaisesRegex(operation_lock.OperationBusyError, "not trusted"):
                operation_lock.validate_coordination_token(token, ("runtime",))

    def test_corrupt_and_malformed_reservations_are_quarantined_from_admission(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            root = pathlib.Path(temporary)
            corrupt = root / ("reservation-" + "d" * 32 + ".json")
            corrupt.write_text("{", encoding="utf-8")
            malformed = root / ("reservation-" + "e" * 32 + ".json")
            malformed.write_text("{}", encoding="utf-8")
            self.assertEqual(operation_lock.operation_state()["reservations"], [])
            self.assertFalse(corrupt.exists())
            self.assertFalse(malformed.exists())

    def test_operation_root_rejects_symlink_world_access_and_inaccessible_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            with mock.patch.object(operation_lock, "OPERATION_ROOT", link):
                with self.assertRaisesRegex(RuntimeError, "not a trusted directory"):
                    operation_lock.ensure_root()

            real.chmod(0o777)
            with mock.patch.object(operation_lock, "OPERATION_ROOT", real):
                with self.assertRaisesRegex(RuntimeError, "other users"):
                    operation_lock.ensure_root()

            real.chmod(0o770)
            with (
                mock.patch.object(operation_lock, "OPERATION_ROOT", real),
                mock.patch.object(operation_lock.os, "access", return_value=False),
            ):
                with self.assertRaises(PermissionError):
                    operation_lock.ensure_root()

    def test_reservation_rejects_invalid_ttl_and_token_shapes(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            with self.assertRaisesRegex(ValueError, "between 30 and 3600"):
                operation_lock.reserve_operation("bad", ("runtime",), ttl_seconds=1)
            with self.assertRaisesRegex(ValueError, "Invalid operation reservation token"):
                operation_lock.cancel_reservation("not-a-token")
            with self.assertRaisesRegex(operation_lock.OperationBusyError, "token is malformed"):
                operation_lock.validate_coordination_token("bad", ("runtime",))

    def test_named_lock_is_created_with_final_mode_atomically(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(operation_lock, "OPERATION_ROOT", pathlib.Path(temporary)),
        ):
            previous = __import__("os").umask(0)
            try:
                handle = operation_lock._open_lock("storage")
                handle.close()
            finally:
                __import__("os").umask(previous)
            mode = (pathlib.Path(temporary) / "storage.lock").stat().st_mode & 0o777
            self.assertEqual(mode, 0o660)


if __name__ == "__main__":
    unittest.main()
