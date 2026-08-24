from __future__ import annotations

import pathlib
import stat
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_guarded_apply as guarded  # noqa: E402


class GuardedApplyTests(unittest.TestCase):
    def executable(self, path: pathlib.Path, body: str) -> pathlib.Path:
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_arm_uses_real_systemd_run_with_transient_timer(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            log = root / "log"
            systemctl = self.executable(
                root / "systemctl",
                f'printf "systemctl:%s\\n" "$*" >> {log}\nif [ "$1" = "is-active" ]; then exit 3; fi\nexit 0\n',
            )
            systemd_run = self.executable(
                root / "systemd-run",
                f'printf "systemd-run:%s\\n" "$*" >> {log}\nexit 0\n',
            )

            result = guarded.arm(
                ["/nix/store/rollback", "--restore"],
                timeout_seconds=45,
                unit="nas-test-rollback",
                systemd_run=str(systemd_run),
                systemctl=str(systemctl),
            )

            self.assertTrue(result["armed"])
            text = log.read_text(encoding="utf-8")
            self.assertIn("systemd-run:--unit=nas-test-rollback --on-active=45s", text)
            self.assertIn("--timer-property=AccuracySec=1s", text)
            self.assertIn("-- /nix/store/rollback --restore", text)
            self.assertNotIn("systemctl:run ", text)

    def test_cancel_stops_timer_and_refuses_active_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            log = root / "log"
            systemctl = self.executable(
                root / "systemctl",
                f'printf "%s\\n" "$*" >> {log}\nif [ "$1" = "is-active" ]; then exit 3; fi\nexit 0\n',
            )
            result = guarded.cancel(unit="nas-test-rollback", systemctl=str(systemctl))
            self.assertFalse(result["armed"])
            text = log.read_text(encoding="utf-8")
            self.assertIn("stop nas-test-rollback.timer", text)
            self.assertIn("is-active nas-test-rollback.service", text)

    def test_cancel_fails_if_rollback_already_started(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            systemctl = self.executable(
                root / "systemctl",
                'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n',
            )
            with self.assertRaisesRegex(guarded.GuardedApplyError, "already started"):
                guarded.cancel(unit="nas-test-rollback", systemctl=str(systemctl))

    def test_rejects_empty_rollback_command(self) -> None:
        with self.assertRaisesRegex(guarded.GuardedApplyError, "must not be empty"):
            guarded.arm([], unit="nas-test-rollback")


if __name__ == "__main__":
    unittest.main()
