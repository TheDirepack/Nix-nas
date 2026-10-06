from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "services"))
import nas_setup as setup  # noqa: E402


class RegenerationTimerTests(unittest.TestCase):
    def exercise(self, *, syncthing=True, fail_at=None, timer_failure=False, initially_active=None):
        active = {"identity-second.timer", "syncthing.timer"} if initially_active is None else set(initially_active)
        triggers = {
            "nas-identity-sync.service": "identity-first.timer identity-second.timer",
            "nas-syncthing-sync.service": "syncthing.timer",
        }
        calls = []
        drained = set()

        def command(argv, **kwargs):
            calls.append(list(argv))
            if argv[:2] == ["systemctl", "show"]:
                return setup.Completed(tuple(argv), triggers[argv[-1]], "")
            if argv[:2] == ["systemctl", "is-active"]:
                return setup.Completed(tuple(argv), "", "", 0 if argv[-1] in active else 3)
            if argv[:2] == ["systemctl", "stop"]:
                if "authentik.service" in argv:
                    if active:
                        raise setup.SetupError("Job for postgresql.service canceled by timer dependency start")
                    self.assertIn("nas-identity-sync.service", drained)
                    if syncthing:
                        self.assertIn("nas-syncthing-sync.service", drained)
                if timer_failure and any(unit.endswith(".timer") for unit in argv[2:]):
                    raise setup.SetupError("timer stop failed")
                active.difference_update(argv[2:])
                drained.update(unit for unit in argv[2:] if unit in triggers)
            if argv[0] == fail_at:
                raise setup.SetupError("injected regeneration failure")
            if argv[:2] == ["systemctl", "start"]:
                active.update(unit for unit in argv[2:] if unit.endswith(".timer"))
            return setup.Completed(tuple(argv), "", "")

        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "authentik").mkdir()
            (root / "postgresql").mkdir()
            with (
                mock.patch.object(setup, "SYNCTHING_ENABLED", syncthing),
                mock.patch.object(setup, "run_root", side_effect=command),
            ):
                if fail_at or timer_failure:
                    with self.assertRaisesRegex(setup.SetupError, "injected|timer stop failed"):
                        setup.regenerate_boot_identity_databases(root)
                else:
                    result = setup.regenerate_boot_identity_databases(root)
                    self.assertEqual(result, {"regenerated": True, "bootSide": True})
        return calls, active

    def test_discovers_all_timers_and_drains_jobs_before_identity_shutdown(self):
        calls, active = self.exercise()
        self.assertEqual(active, {"identity-second.timer", "syncthing.timer"})
        selector = calls.index(["systemctl", "start", "nas-bootstrap-runtime-select.service"])
        timer_starts = [
            index
            for index, call in enumerate(calls)
            if call[:2] == ["systemctl", "start"] and any(item.endswith(".timer") for item in call[2:])
        ]
        self.assertTrue(timer_starts)
        self.assertTrue(all(index > selector for index in timer_starts))
        self.assertFalse(any("identity-first.timer" in calls[index] for index in timer_starts))

    def test_failure_keeps_schedulers_paused_for_manual_recovery(self):
        calls, active = self.exercise(fail_at="find")
        self.assertFalse(active)
        self.assertFalse(any(call[:2] == ["systemctl", "start"] for call in calls))

    def test_initially_inactive_timers_remain_inactive_after_regeneration(self):
        calls, active = self.exercise(initially_active=set())
        self.assertFalse(active)
        self.assertFalse(
            any(
                call[:2] == ["systemctl", "start"] and any(item.endswith(".timer") for item in call[2:])
                for call in calls
            )
        )

    def test_failed_timer_stop_prevents_identity_shutdown_and_deletion(self):
        calls, _active = self.exercise(timer_failure=True)
        self.assertFalse(any(call[0] == "find" for call in calls))
        self.assertFalse(any(call[:2] == ["systemctl", "stop"] and "authentik.service" in call for call in calls))

    def test_disabled_syncthing_does_not_query_or_stop_its_missing_service(self):
        with (
            mock.patch.object(setup, "SYNCTHING_ENABLED", False),
            mock.patch.object(setup, "run_root", return_value=setup.Completed((), "", "")) as root,
        ):
            setup.regenerate_boot_identity_databases(pathlib.Path("/nonexistent-test-control-root"))
        self.assertFalse(any("nas-syncthing-sync.service" in call.args[0] for call in root.call_args_list))
        root.assert_any_call(["systemctl", "stop", "nas-identity-sync.service"])


if __name__ == "__main__":
    unittest.main()
