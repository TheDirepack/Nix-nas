from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest

from repo_test_utils import ROOT, text


class QemuProcessTests(unittest.TestCase):
    def identify(self, pidfile: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; nas_qemu_pid_from_pidfile "$2"; status=$?; echo "$QEMU_PID"; exit "$status"',
                "test",
                str(ROOT / "scripts/lib/nas-qemu-process.sh"),
                str(pidfile),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_native_and_nix_wrapped_executable_names_are_recognized(self):
        sleep = shutil.which("sleep")
        self.assertIsNotNone(sleep)
        assert sleep is not None
        for name in ("qemu-system-x86_64", ".qemu-system-x86_64-wrapped"):
            for deleted in (False, True):
                with self.subTest(name=name, deleted=deleted), tempfile.TemporaryDirectory() as raw:
                    root = pathlib.Path(raw)
                    executable = root / name
                    shutil.copyfile(sleep, executable)
                    executable.chmod(0o700)
                    child = subprocess.Popen([str(executable), "60"])
                    try:
                        pidfile = root / "qemu.pid"
                        pidfile.write_text(str(child.pid))
                        if deleted:
                            executable.unlink()
                        result = self.identify(pidfile)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), str(child.pid))
                    finally:
                        child.terminate()
                        child.wait(timeout=10)

    def test_unrelated_executable_is_rejected_despite_spoofed_argv_zero(self):
        child = subprocess.Popen(["bash", "-c", "exec -a qemu-system-x86_64 sleep 60"])
        try:
            with tempfile.TemporaryDirectory() as raw:
                pidfile = pathlib.Path(raw) / "qemu.pid"
                pidfile.write_text(str(child.pid))
                result = self.identify(pidfile)
                self.assertEqual(result.returncode, 2)
                self.assertIn("refusing to signal", result.stderr)
                self.assertEqual(result.stdout.strip(), "")
                self.assertIsNone(child.poll())
                self.assertTrue(pidfile.exists())
        finally:
            child.terminate()
            child.wait(timeout=10)

    def test_wrapper_name_matching_is_exact(self):
        sleep = shutil.which("sleep")
        assert sleep is not None
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            executable = root / ".qemu-system-x86_64-wrapped-unrelated"
            shutil.copyfile(sleep, executable)
            executable.chmod(0o700)
            child = subprocess.Popen([str(executable), "60"])
            try:
                pidfile = root / "qemu.pid"
                pidfile.write_text(str(child.pid))
                self.assertEqual(self.identify(pidfile).returncode, 2)
                self.assertIsNone(child.poll())
            finally:
                child.terminate()
                child.wait(timeout=10)

    def test_final_browser_uses_shared_process_guard_and_stop(self):
        source = text("scripts/qemu-final-browser.sh")
        self.assertIn('source "$ROOT/scripts/lib/nas-qemu-process.sh"', source)
        self.assertIn('nas_qemu_stop_pidfile "$PIDFILE" 20', source)
        self.assertNotIn("qemu_pid_from_pidfile()", source)
        self.assertNotIn('readlink -f "/proc/', source)
