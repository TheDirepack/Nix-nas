from __future__ import annotations

import pathlib
import stat
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_guarded_apply as guarded  # noqa: E402


def _idle_systemctl(root: pathlib.Path, log: pathlib.Path) -> pathlib.Path:
    ctl = root / "systemctl"
    ctl.write_text(
        "#!/bin/sh\nset -eu\n"
        f'printf "%s\\n" "$*" >> {log}\n'
        'if [ "$1" = "is-active" ]; then exit 3; fi\n'
        'if [ "$1" = "is-failed" ]; then exit 1; fi\n'
        'if [ "$1" = "show" ]; then printf "LoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nResult=\\n"; exit 0; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    ctl.chmod(ctl.stat().st_mode | stat.S_IXUSR)
    return ctl


def _systemd_run(root: pathlib.Path, log: pathlib.Path) -> pathlib.Path:
    run = root / "systemd-run"
    run.write_text(
        "#!/bin/sh\nset -eu\n" f'printf "systemd-run:%s\\n" "$*" >> {log}\n' "exit 0\n",
        encoding="utf-8",
    )
    run.chmod(run.stat().st_mode | stat.S_IXUSR)
    return run


class GuardedApplyTests(unittest.TestCase):
    def executable(self, path: pathlib.Path, body: str) -> pathlib.Path:
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_arm_uses_real_systemd_run_with_transient_timer(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            log = root / "log"
            state_dir = root / "guard-state"
            systemctl = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)

            result = guarded.arm(
                ["/nix/store/rollback", "--restore"],
                timeout_seconds=45,
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(systemctl),
                state_dir=str(state_dir),
            )

            self.assertTrue(result["armed"])
            self.assertEqual(result["state"], "armed")
            text = log.read_text(encoding="utf-8")
            self.assertIn("--unit=nas-test-rollback --on-active=45s", text)
            self.assertIn("--timer-property=AccuracySec=1s", text)
            self.assertIn("fired", text)
            self.assertIn("/nix/store/rollback --restore", text)
            self.assertNotIn("systemctl:run ", text)
            status = guarded.status(unit="nas-test-rollback", systemctl=str(systemctl), state_dir=str(state_dir))
            self.assertEqual(status["state"], "armed")

    def test_never_fired_cancellation_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            log = root / "log"
            state_dir = root / "guard-state"
            systemctl = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)
            guarded.arm(
                ["/nix/store/rollback"],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(systemctl),
                state_dir=str(state_dir),
            )
            result = guarded.cancel(unit="nas-test-rollback", systemctl=str(systemctl), state_dir=str(state_dir))
            self.assertFalse(result["armed"])
            self.assertEqual(result["state"], "cancelled")
            text = log.read_text(encoding="utf-8")
            self.assertIn("stop nas-test-rollback.timer", text)
            self.assertNotIn("reset-failed", text)

    def test_cancel_without_durable_state_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            log = root / "log"
            state_dir = root / "guard-state"
            systemctl = _idle_systemctl(root, log)
            with self.assertRaisesRegex(guarded.GuardedApplyError, "no durable guard state"):
                guarded.cancel(unit="nas-test-rollback", systemctl=str(systemctl), state_dir=str(state_dir))

    def test_cancel_refuses_active_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            log = root / "log"
            state_dir = root / "guard-state"
            idle = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)
            guarded.arm(
                ["/nix/store/rollback"],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            active = self.executable(
                root / "systemctl-active",
                f'printf "%s\\n" "$*" >> {log}\nif [ "$1" = "is-active" ]; then exit 0; fi\n'
                'if [ "$1" = "is-failed" ]; then exit 1; fi\n'
                'if [ "$1" = "show" ]; then printf "LoadState=loaded\\nActiveState=activating\\nSubState=start\\nResult=\\n"; exit 0; fi\n'
                "exit 0\n",
            )
            with self.assertRaisesRegex(guarded.GuardedApplyError, "already (started|claimed|running)"):
                guarded.cancel(unit="nas-test-rollback", systemctl=str(active), state_dir=str(state_dir))
            status = guarded.status(unit="nas-test-rollback", systemctl=str(active), state_dir=str(state_dir))
            self.assertEqual(status["state"], "armed")

    def test_cancel_refuses_failed_rollback_and_preserves_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_dir = root / "guard-state"
            log = root / "log"
            idle = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)
            rollback = self.executable(root / "rollback-fail", "exit 3\n")
            guarded.arm(
                [str(rollback)],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            outcome = guarded.fired(
                [str(rollback)],
                unit="nas-test-rollback",
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            self.assertEqual(outcome["state"], "failed")
            failed_ctl = self.executable(
                root / "systemctl-failed",
                f'printf "%s\\n" "$*" >> {log}\nif [ "$1" = "is-active" ]; then exit 3; fi\n'
                'if [ "$1" = "is-failed" ]; then exit 0; fi\n'
                'if [ "$1" = "show" ]; then printf "LoadState=loaded\\nActiveState=failed\\nSubState=failed\\nResult=exit-code\\n"; exit 0; fi\n'
                "exit 0\n",
            )
            with self.assertRaisesRegex(guarded.GuardedApplyError, "already failed"):
                guarded.cancel(unit="nas-test-rollback", systemctl=str(failed_ctl), state_dir=str(state_dir))
            text = log.read_text(encoding="utf-8")
            self.assertNotIn("reset-failed", text)
            status = guarded.status(unit="nas-test-rollback", systemctl=str(failed_ctl), state_dir=str(state_dir))
            self.assertEqual(status["state"], "failed")
            self.assertIn("exitCode", status)

    def test_cancel_refuses_completed_and_collected_with_distinct_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_dir = root / "guard-state"
            log = root / "log"
            idle = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)
            rollback = self.executable(root / "rollback-ok", "exit 0\n")
            guarded.arm(
                [str(rollback)],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            outcome = guarded.fired(
                [str(rollback)],
                unit="nas-test-rollback",
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            self.assertEqual(outcome["state"], "completed")
            completed_ctl = self.executable(
                root / "systemctl-done",
                f'printf "%s\\n" "$*" >> {log}\nif [ "$1" = "is-active" ]; then exit 3; fi\n'
                'if [ "$1" = "is-failed" ]; then exit 1; fi\n'
                'if [ "$1" = "show" ]; then printf "LoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nResult=success\\n"; exit 0; fi\n'
                "exit 0\n",
            )
            with self.assertRaisesRegex(guarded.GuardedApplyError, "already completed"):
                guarded.cancel(unit="nas-test-rollback", systemctl=str(completed_ctl), state_dir=str(state_dir))
            collected = guarded.collect(unit="nas-test-rollback", systemctl=str(idle), state_dir=str(state_dir))
            self.assertEqual(collected["state"], "collected")
            with self.assertRaisesRegex(guarded.GuardedApplyError, "already collected"):
                guarded.cancel(unit="nas-test-rollback", systemctl=str(completed_ctl), state_dir=str(state_dir))

    def test_new_arm_never_erases_unresolved_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_dir = root / "guard-state"
            log = root / "log"
            idle = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)
            rollback = self.executable(root / "rollback-fail", "exit 3\n")
            guarded.arm(
                [str(rollback)],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            guarded.fired([str(rollback)], unit="nas-test-rollback", systemctl=str(idle), state_dir=str(state_dir))
            with self.assertRaisesRegex(guarded.GuardedApplyError, "unresolved|already failed"):
                guarded.arm(
                    [str(rollback)],
                    unit="nas-test-rollback",
                    systemd_run=str(systemd_run),
                    systemctl=str(idle),
                    state_dir=str(state_dir),
                )
            text = log.read_text(encoding="utf-8")
            self.assertNotIn("reset-failed", text)
            status = guarded.status(unit="nas-test-rollback", systemctl=str(idle), state_dir=str(state_dir))
            self.assertEqual(status["state"], "failed")
            guarded.collect(unit="nas-test-rollback", systemctl=str(idle), state_dir=str(state_dir))
            second = guarded.arm(
                [str(rollback)],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            self.assertEqual(second["state"], "armed")

    def test_cancel_wins_race_aborts_fired_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_dir = root / "guard-state"
            log = root / "log"
            idle = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)
            marker = root / "rollback-ran"
            rollback = self.executable(root / "rollback-marker", f'touch {marker}\nexit 0\n')
            guarded.arm(
                [str(rollback)],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            guarded.cancel(unit="nas-test-rollback", systemctl=str(idle), state_dir=str(state_dir))
            outcome = guarded.fired(
                [str(rollback)],
                unit="nas-test-rollback",
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            self.assertEqual(outcome["state"], "cancelled")
            self.assertFalse(marker.exists())

    def test_fired_wins_race_blocks_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_dir = root / "guard-state"
            log = root / "log"
            idle = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)
            rollback = self.executable(root / "rollback-ok", "exit 0\n")
            guarded.arm(
                [str(rollback)],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            fired_result = guarded.fired(
                [str(rollback)],
                unit="nas-test-rollback",
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            self.assertEqual(fired_result["state"], "completed")
            done_ctl = self.executable(
                root / "systemctl-done",
                f'printf "%s\\n" "$*" >> {log}\nif [ "$1" = "is-active" ]; then exit 3; fi\n'
                'if [ "$1" = "is-failed" ]; then exit 1; fi\n'
                'if [ "$1" = "show" ]; then printf "LoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nResult=success\\n"; exit 0; fi\n'
                "exit 0\n",
            )
            with self.assertRaisesRegex(guarded.GuardedApplyError, "already completed"):
                guarded.cancel(unit="nas-test-rollback", systemctl=str(done_ctl), state_dir=str(state_dir))

    def test_injected_concurrent_race_resolves_to_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_dir = root / "guard-state"
            log = root / "log"
            idle = _idle_systemctl(root, log)
            systemd_run = _systemd_run(root, log)
            marker = root / "rollback-ran"
            rollback = self.executable(root / "rollback-slow", f'sleep 0.2\ntouch {marker}\nexit 0\n')
            guarded.arm(
                [str(rollback)],
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(idle),
                state_dir=str(state_dir),
            )
            barrier = threading.Barrier(2)
            results: dict[str, str] = {}

            def do_cancel() -> None:
                barrier.wait(timeout=10)
                try:
                    guarded.cancel(unit="nas-test-rollback", systemctl=str(idle), state_dir=str(state_dir))
                    results["cancel"] = "ok"
                except Exception as exc:  # noqa: BLE001
                    results["cancel"] = f"error:{exc}"

            def do_fired() -> None:
                barrier.wait(timeout=10)
                try:
                    outcome = guarded.fired(
                        [str(rollback)], unit="nas-test-rollback", systemctl=str(idle), state_dir=str(state_dir)
                    )
                    results["fired"] = outcome["state"]
                except Exception as exc:  # noqa: BLE001
                    results["fired"] = f"error:{exc}"

            first = threading.Thread(target=do_cancel)
            second = threading.Thread(target=do_fired)
            first.start()
            second.start()
            first.join(timeout=30)
            second.join(timeout=30)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertIn("cancel", results)
            self.assertIn("fired", results)
            if results["cancel"] == "ok":
                self.assertEqual(results["fired"], "cancelled")
                self.assertFalse(marker.exists())
            else:
                self.assertIn("already", results["cancel"])
                self.assertEqual(results["fired"], "completed")
                self.assertTrue(marker.exists())
            status = guarded.status(unit="nas-test-rollback", systemctl=str(idle), state_dir=str(state_dir))
            self.assertIn(status["state"], ("cancelled", "claimed", "completed", "failed"))
            if results["cancel"] == "ok":
                self.assertEqual(status["state"], "cancelled")
                self.assertFalse(marker.exists())
            else:
                self.assertIn("already", results["cancel"])
                self.assertIn(status["state"], ("completed", "claimed", "failed"))
                self.assertTrue(marker.exists())

    def test_rejects_empty_rollback_command(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state_dir = pathlib.Path(raw) / "guard-state"
            with self.assertRaisesRegex(guarded.GuardedApplyError, "must not be empty"):
                guarded.arm([], unit="nas-test-rollback", state_dir=str(state_dir))


if __name__ == "__main__":
    unittest.main()
