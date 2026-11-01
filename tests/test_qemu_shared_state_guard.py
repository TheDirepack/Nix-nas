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
                    "bash",
                    "-c",
                    script,
                    "guard-fixture",
                    str(HELPER),
                    str(pidfile),
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
                rejected = self.guard(pid_exists=True, status=0, persistent=persistent, reuse=reuse, complete=complete)
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

    def test_competing_installer_and_persistent_start_are_excluded_by_flock(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            lock = root / "cache.shared-qemu.lock"
            release = root / "release"
            holder_script = (
                'set -euo pipefail; source "$1"; '
                'nas_qemu_acquire_shared_state_lock "$2"; '
                'printf "locked\\n"; '
                'while [[ ! -e "$3" ]]; do sleep 0.05; done'
            )
            contender_script = (
                'set -euo pipefail; source "$1"; '
                'nas_qemu_acquire_shared_state_lock "$2"'
            )
            holder = subprocess.Popen(
                ["bash", "-c", holder_script, "holder", str(HELPER), str(lock), str(release)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                holder_stdout = holder.stdout
                assert holder_stdout is not None
                self.assertEqual(holder_stdout.readline().strip(), "locked")
                blocked = subprocess.run(
                    ["bash", "-c", contender_script, "contender", str(HELPER), str(lock)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                self.assertNotEqual(blocked.returncode, 0)
                self.assertIn("already owned", blocked.stderr)
                self.assertTrue(lock.exists(), "lock inode must outlive the disposable VM cache")
            finally:
                release.touch()
                stdout, stderr = holder.communicate(timeout=5)
                self.assertEqual(holder.returncode, 0, stdout + stderr)

            acquired = subprocess.run(
                ["bash", "-c", contender_script, "contender", str(HELPER), str(lock)],
                capture_output=True, text=True, check=False, timeout=5,
            )
            self.assertEqual(acquired.returncode, 0, acquired.stderr)

    def test_all_shared_state_mutations_acquire_lock_before_touching_disks(self):
        source = RUNNER.read_text(encoding="utf-8")
        install = source.split("run_installer() {", 1)[1].split("run_installer_with_timeout() {", 1)[0]
        self.assertLess(
            install.index("nas_qemu_acquire_shared_state_lock"),
            install.index('rm -f "$os_disk" "$data_disk"'),
        )
        self.assertIn('exec {NAS_QEMU_SHARED_LOCK_FD}>&-', install)
        self.assertIn('persistent-stop)\\n    validate_state_path\\n    nas_qemu_acquire_shared_state_lock', source)
        self.assertIn("cannot clean VM cache while another shared QEMU operation is active", source)
        self.assertIn("persistent reset cannot run while a shared QEMU operation is active", source)

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
