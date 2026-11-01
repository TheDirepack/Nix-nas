"""Fail-closed shared-QEMU installer ownership tests (no VM or host disks)."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/lib/nas-qemu-process.sh"
RUNNER = ROOT / "scripts/qemu-test.sh"


class SharedQemuInstallStateTests(unittest.TestCase):
    def guard(self, *, pid_exists: bool, status: int, persistent: bool, reuse: bool, complete: bool):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            pidfile = root / "qemu.pid"
            paths = [root / name for name in ("os.qcow2", "data.qcow2", "admin.key", "installed")]
            if pid_exists:
                pidfile.write_text("456\n", encoding="ascii")
            if complete:
                for path in paths:
                    path.write_bytes(b"existing-state")
            script = (
                'set -euo pipefail; source "$1"; '
                'nas_qemu_pid_from_pidfile() { return "$FAKE_PID_STATUS"; }; '
                'nas_qemu_guard_shared_installer_state "$2" "$3" "$4" "$5" "$6" "$7" "$8"'
            )
            result = subprocess.run(
                [
                    "bash", "-c", script, "guard-fixture",
                    str(HELPER), str(pidfile),
                    "1" if persistent else "0",
                    "1" if reuse else "0",
                    *(str(path) for path in paths),
                ],
                env={**os.environ, "FAKE_PID_STATUS": str(status)},
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            self.assertEqual(pidfile.exists(), pid_exists)
            if complete:
                for path in paths:
                    self.assertEqual(path.read_bytes(), b"existing-state")
            return result

    def test_installer_refuses_live_persistent_qemu_before_touching_disks(self):
        result = self.guard(pid_exists=True, status=0, persistent=False, reuse=False, complete=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("persistent VM is running", result.stderr)

    def test_explicit_persistent_reuse_requires_complete_existing_files(self):
        accepted = self.guard(pid_exists=True, status=0, persistent=True, reuse=True, complete=True)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for persistent, reuse, complete in ((True, False, True), (True, True, False)):
            with self.subTest(persistent=persistent, reuse=reuse, complete=complete):
                rejected = self.guard(
                    pid_exists=True, status=0, persistent=persistent, reuse=reuse, complete=complete
                )
                self.assertEqual(rejected.returncode, 1)

    def test_foreign_pid_must_not_be_treated_as_stale(self):
        result = self.guard(pid_exists=True, status=2, persistent=False, reuse=False, complete=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("foreign PID", result.stderr)

    def test_stale_or_missing_pidfile_can_be_recovered(self):
        stale = self.guard(pid_exists=True, status=1, persistent=False, reuse=False, complete=False)
        self.assertEqual(stale.returncode, 0, stale.stderr)
        missing = self.guard(pid_exists=False, status=0, persistent=False, reuse=False, complete=False)
        self.assertEqual(missing.returncode, 0, missing.stderr)

    def test_guard_precedes_installer_cleanup_and_disk_replacement(self):
        source = RUNNER.read_text(encoding="utf-8")
        begin = source.index("run_installer() {")
        guard = source.index("nas_qemu_guard_shared_installer_state", begin)
        cleanup = source.index("trap cleanup_vm EXIT INT TERM", begin)
        disk_replace = source.index('rm -f "$os_disk" "$data_disk"', begin)
        self.assertLess(guard, cleanup)
        self.assertLess(guard, disk_replace)
        self.assertIn('[[ "$vm_started_by_this_run" == true ]] || return 0', source)
        self.assertGreaterEqual(source[begin:].count("nas_qemu_guard_shared_installer_state"), 3)


if __name__ == "__main__":
    unittest.main()
