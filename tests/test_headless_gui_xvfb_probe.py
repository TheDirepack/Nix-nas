"""Opt-in local Linux display proof: no NixOS/Podman claim from host tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "headless_gui_xvfb_probe.py"
spec = importlib.util.spec_from_file_location("headless_gui_xvfb_probe", MODULE)
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

REQUIRED = ("Xvfb", "xauth", "xdpyinfo")
HAVE = all(shutil.which(p) for p in REQUIRED)


class AlwaysAvailableContractTests(unittest.TestCase):
    def test_invalid_geometry_is_rejected_before_launch(self):
        with mock.patch.object(probe, "_require") as require:
            for options in ({"width": 0}, {"height": 10}, {"depth": 12}):
                with self.subTest(options=options):
                    with self.assertRaises(ValueError):
                        with probe.private_xvfb(**options):
                            self.fail("invalid geometry accepted")
            require.assert_not_called()

    @unittest.skipUnless(HAVE, "needs Xvfb to verify a real startup retry")
    def test_readiness_timeout_retries_without_abandoning_healthy_server(self):
        real_run = subprocess.run
        forced = [False]

        def occasionally_slow(argv, *args, **kwargs):
            if argv[0] == "xdpyinfo" and not forced[0]:
                forced[0] = True
                raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))
            return real_run(argv, *args, **kwargs)

        with mock.patch.object(probe.subprocess, "run", side_effect=occasionally_slow):
            with probe.private_xvfb() as (_display, _env, _root, server):
                self.assertIsNone(server.poll())
        self.assertTrue(forced[0], "timeout test did not exercise retry")

    def test_missing_external_tools_fail_explicitly(self):
        with mock.patch.object(probe.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Xvfb.*xauth.*xdpyinfo"):
                with probe.private_xvfb():
                    self.fail("missing tools accepted")


@unittest.skipUnless(HAVE, "needs an installed Xvfb, xauth and xdpyinfo")
class PrivateDisplaySmokeTest(unittest.TestCase):
    def test_process_and_credentials_cleanup_without_pillow(self):
        with probe.private_xvfb() as (_display, env, path, proc):
            self.assertIsNone(proc.poll())
            authority = Path(env["XAUTHORITY"])
            self.assertTrue(authority.exists())
        self.assertIsNotNone(proc.poll(), "owned Xvfb must be reaped")
        self.assertFalse(path.exists(), "private directory must be removed")
        self.assertFalse(authority.exists(), "secret Xauthority file must be removed")

    def test_cleanup_when_owned_xvfb_is_killed(self):
        with probe.private_xvfb() as (_display, env, path, proc):
            self.assertIsNone(proc.poll())
            authority = Path(env["XAUTHORITY"])
            proc.kill()
            proc.wait(timeout=3)
        self.assertIsNotNone(proc.poll(), "crashed Xvfb must be reaped")
        self.assertFalse(path.exists(), "crashed Xvfb's credentials must be cleaned up")
        self.assertFalse(authority.exists())

    def test_process_and_credentials_cleanup_on_body_failure(self):
        proc = None
        path = None
        with self.assertRaisesRegex(RuntimeError, "injected failure"):
            with probe.private_xvfb() as (_display, _env, directory, server):
                proc, path = server, directory
                raise RuntimeError("injected failure")
        self.assertIsNotNone(proc)
        self.assertIsNotNone(proc.poll(), "owned Xvfb must be reaped on exception")
        self.assertFalse(path.exists(), "private directory must be removed on exception")

    def test_authentication_and_screenshot(self):
        with probe.private_xvfb(width=640, height=480) as (display, env, path, _proc):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            self.assertEqual(Path(env["XAUTHORITY"]).stat().st_mode & 0o777, 0o600)
            self.assertEqual(subprocess.run(["xdpyinfo"], env=env, capture_output=True, timeout=2).returncode, 0)
            # Prove a separate, incorrect cookie cannot inspect the display.
            bad = dict(env, XAUTHORITY=str(path / "not-a-cookie"))
            self.assertNotEqual(subprocess.run(["xdpyinfo"], env=bad, capture_output=True, timeout=2).returncode, 0)
            try:
                import PIL  # noqa: F401
            except ImportError:
                self.skipTest("Pillow screenshot backend not installed")
            with tempfile.TemporaryDirectory() as out:
                file = Path(out) / "screen.png"
                self.assertEqual(probe.snapshot_png(env, file), (640, 480))
                self.assertTrue(file.is_file())
        self.assertFalse(path.exists(), "private runtime directory must be cleaned up")

    @unittest.skipUnless(shutil.which("xterm"), "needs a sample GUI application (xterm)")
    def test_actual_gui_window_changes_capture(self):
        try:
            from PIL import Image, ImageChops  # noqa: F401
        except ImportError:
            self.skipTest("Pillow is not installed")
        with probe.private_xvfb(width=640, height=480) as (_display, env, _root, _proc):
            with tempfile.TemporaryDirectory() as out:
                before = Path(out) / "before.png"
                after = Path(out) / "after.png"
                probe.snapshot_png(env, before)
                app = subprocess.Popen(
                    ["xterm", "-geometry", "40x10+20+20", "-bg", "white", "-fg", "black",
                     "-e", "sh", "-c", "sleep 4"],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                try:
                    import time
                    for _ in range(20):
                        time.sleep(0.1)
                        if app.poll() is not None:
                            self.fail("example GUI exited before screenshot")
                        probe.snapshot_png(env, after)
                        if ImageChops.difference(Image.open(before), Image.open(after)).getbbox():
                            break
                    else:
                        self.fail("X11 application did not produce any visible pixels")
                finally:
                    app.terminate()
                    app.wait(timeout=3)
                    if app.stderr:
                        app.stderr.close()

    def test_two_concurrent_displays_cannot_reuse_credentials(self):
        with probe.private_xvfb() as (a, env_a, root_a, _proc_a):
            with probe.private_xvfb() as (b, env_b, _, _proc_b):
                self.assertNotEqual(a, b)
                self.assertEqual(subprocess.run(["xdpyinfo"], env=env_a, capture_output=True, timeout=2).returncode, 0)
                self.assertEqual(subprocess.run(["xdpyinfo"], env=env_b, capture_output=True, timeout=2).returncode, 0)
                # Re-key B's real cookie to display A. This tests cookie rejection,
                # rather than merely failing because B's authority lacks an A entry.
                b_cookie_entries = subprocess.run(
                    ["xauth", "-f", env_b["XAUTHORITY"], "list", b],
                    capture_output=True, text=True, check=True, timeout=2,
                ).stdout.strip().splitlines()
                self.assertEqual(len(b_cookie_entries), 1)
                b_cookie = b_cookie_entries[0].split()[-1]
                self.assertEqual(len(b_cookie), 32)
                crossed_authority = root_a / "crossed-auth"
                crossed_authority.touch(mode=0o600)
                crossed_authority.chmod(0o600)
                subprocess.run(
                    ["xauth", "-f", str(crossed_authority), "add", a, "MIT-MAGIC-COOKIE-1", b_cookie],
                    capture_output=True, text=True, check=True, timeout=2,
                )
                crossed = dict(env_a, XAUTHORITY=str(crossed_authority))
                self.assertNotEqual(
                    subprocess.run(["xdpyinfo"], env=crossed, capture_output=True, timeout=2).returncode, 0
                )


if __name__ == "__main__":
    unittest.main()
