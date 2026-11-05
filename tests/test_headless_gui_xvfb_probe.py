"""Opt-in local Linux display proof: no NixOS/Podman claim from host tests."""

from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "headless_gui_xvfb_probe.py"
spec = importlib.util.spec_from_file_location("headless_gui_xvfb_probe", MODULE)
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

REQUIRED = ("Xvfb", "xauth", "xdpyinfo")
HAVE = all(shutil.which(p) for p in REQUIRED)
XTERM = shutil.which("xterm")
HAVE_PIL = importlib.util.find_spec("PIL") is not None
SOCKET_DIR = Path("/tmp/.X11-unix")
# Interior pixel of the 100x30 window at +0+0 on a 640x480 screen; the window
# edge and root background make the first few pixels unreliable.
SAMPLE_POINT = (200, 100)


def _display_paths(number: int) -> tuple[Path, Path]:
    return SOCKET_DIR / f"X{number}", Path(f"/tmp/.X{number}-lock")


def _discard_display_paths(number: int) -> None:
    for path in _display_paths(number):
        path.unlink(missing_ok=True)


@contextmanager
def unauthenticated_display():
    """A real Xvfb with `-ac`: the pre-existing server the probe must never adopt."""
    for number in range(1500, 1520):
        socket_path, lock_path = _display_paths(number)
        if socket_path.exists() or lock_path.exists():
            continue
        proc = subprocess.Popen(
            ["Xvfb", f":{number}", "-screen", "0", "320x240x24", "-nolisten", "tcp", "-ac", "-noreset"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            env = dict(os.environ, DISPLAY=f":{number}")
            env.pop("XAUTHORITY", None)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    break
                if subprocess.run(["xdpyinfo"], env=env, capture_output=True, timeout=1).returncode == 0:
                    yield number, env
                    return
                time.sleep(0.05)
            raise RuntimeError(f"could not start the unauthenticated reference display :{number}")
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            _discard_display_paths(number)


def _colour_close(actual, expected, tolerance: int = 32) -> bool:
    return all(abs(left - right) <= tolerance for left, right in zip(actual, expected))


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
                self.assertIsNone(server.returncode)
        self.assertTrue(forced[0], "timeout test did not exercise retry")

    def test_missing_external_tools_fail_explicitly(self):
        with mock.patch.object(probe.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Xvfb.*xauth.*xdpyinfo"):
                with probe.private_xvfb():
                    self.fail("missing tools accepted")

    def test_screenshot_capture_runs_with_a_bounded_deadline(self):
        self.assertIsNotNone(
            getattr(probe, "_CAPTURE_SCRIPT", None),
            "screenshot capture still runs unbounded inside the caller process",
        )
        with tempfile.TemporaryDirectory() as out:
            started = time.monotonic()
            with mock.patch.object(probe, "_CAPTURE_SCRIPT", "import time\ntime.sleep(30)\n"):
                with self.assertRaises(RuntimeError):
                    probe.snapshot_png(
                        {"DISPLAY": ":0", "XAUTHORITY": "/nonexistent"}, Path(out) / "never.png", timeout=0.3
                    )
            self.assertLess(time.monotonic() - started, 3.0, "screenshot capture ignored its deadline")


@unittest.skipUnless(HAVE, "needs an installed Xvfb, xauth and xdpyinfo")
class PrivateDisplaySmokeTest(unittest.TestCase):
    def test_never_yields_a_preexisting_unauthenticated_display(self):
        with unauthenticated_display() as (number, foreign_env):
            self.assertEqual(
                subprocess.run(["xdpyinfo"], env=foreign_env, capture_output=True, timeout=2).returncode,
                0,
                "reference unauthenticated display is not reachable",
            )
            # The retired allocator picked this exact display; the probe must not
            # report a server it did not spawn as its private session.
            with mock.patch.object(probe.secrets, "randbelow", return_value=number - 1000):
                with probe.private_xvfb() as (display, env, _root, proc):
                    self.assertNotEqual(display, f":{number}", "probe adopted a pre-existing unauthenticated display")
                    status = Path(f"/proc/{proc.pid}/status").read_text(encoding="ascii")
                    parent = next(line for line in status.splitlines() if line.startswith("PPid:"))
                    self.assertEqual(int(parent.split()[1]), os.getpid(), "yielded Xvfb is not the probe's child")
                    self.assertEqual(
                        subprocess.run(["xdpyinfo"], env=env, capture_output=True, timeout=2).returncode,
                        0,
                        "yielded display is not usable with its own credential",
                    )

    def test_display_allocation_is_delegated_to_xvfb_displayfd(self):
        launched: list[list[str]] = []
        real_popen = subprocess.Popen

        def record(argv, *args, **kwargs):
            launched.append(list(argv))
            return real_popen(argv, *args, **kwargs)

        with mock.patch.object(probe.subprocess, "Popen", side_effect=record):
            with probe.private_xvfb():
                pass
        servers = [argv for argv in launched if Path(argv[0]).name == "Xvfb"]
        self.assertTrue(servers, "no Xvfb process was launched")
        argv = servers[0]
        self.assertIn("-displayfd", argv, "probe must let Xvfb choose and report the display it owns")
        self.assertFalse(
            [argument for argument in argv if argument.startswith(":")],
            "probe still chooses a display number and must classify collision diagnostics itself",
        )

    def test_xvfb_stderr_cannot_block_the_server(self):
        with probe.private_xvfb() as (_display, _env, root, proc):
            self.assertIsNone(proc.returncode)
            finished = threading.Event()
            failures: list[BaseException] = []
            payload = b"x" * (2 * 1024 * 1024)

            def flood():
                # Writing straight into the server's stderr descriptor can only
                # complete if the probe drained it or bound it to a file.
                try:
                    descriptor = os.open(f"/proc/{proc.pid}/fd/2", os.O_WRONLY | os.O_APPEND)
                    try:
                        offset = 0
                        while offset < len(payload):
                            offset += os.write(descriptor, payload[offset : offset + 65536])
                    finally:
                        os.close(descriptor)
                except BaseException as exc:  # noqa: BLE001 - reported by assertion
                    failures.append(exc)
                finally:
                    finished.set()

            threading.Thread(target=flood, daemon=True).start()
            self.assertTrue(finished.wait(3.0), "Xvfb stderr is an unread pipe; the server can block on it")
            self.assertEqual(failures, [])
            self.assertTrue(
                (root / "xvfb.log").exists(), "server diagnostics must land in the private runtime directory"
            )

    def test_sigkill_removes_only_the_owned_display_artifacts(self):
        number = None
        try:
            with probe.private_xvfb() as (display, _env, _root, proc):
                number = int(display.removeprefix(":"))
                socket_path, lock_path = _display_paths(number)
                self.assertTrue(socket_path.exists(), "display socket missing while the server runs")
                proc.kill()
            self.assertEqual(proc.returncode, -signal.SIGKILL, "context manager must reap the killed server")
            self.assertFalse(socket_path.exists(), "SIGKILL left a stale X11 socket that blocks later sessions")
            self.assertFalse(lock_path.exists(), "SIGKILL left a stale X11 display lock")
        finally:
            if number is not None:
                _discard_display_paths(number)

    def test_artifact_cleanup_spares_a_live_foreign_display(self):
        self.assertTrue(
            hasattr(probe, "_remove_owned_display_artifacts"),
            "probe has no artifact cleanup that verifies ownership",
        )
        with unauthenticated_display() as (number, foreign_env):
            socket_path, _lock_path = _display_paths(number)
            probe._remove_owned_display_artifacts(number, os.getpid(), set())
            self.assertTrue(socket_path.exists(), "cleanup unlinked a socket still served by another process")
            self.assertEqual(
                subprocess.run(["xdpyinfo"], env=foreign_env, capture_output=True, timeout=2).returncode,
                0,
                "cleanup broke the unrelated display",
            )

    def test_artifact_cleanup_keeps_a_lock_owned_by_another_process(self):
        self.assertTrue(
            hasattr(probe, "_remove_owned_display_artifacts"),
            "probe has no artifact cleanup that verifies the lock owner",
        )
        number = next(
            candidate
            for candidate in range(24000, 24050)
            if not any(path.exists() for path in _display_paths(candidate))
        )
        _socket_path, lock_path = _display_paths(number)
        lock_path.write_text(f"{os.getpid() + 1:10d}\n", encoding="ascii")
        try:
            probe._remove_owned_display_artifacts(number, os.getpid(), set())
            self.assertTrue(lock_path.exists(), "cleanup removed another process's display lock")
        finally:
            _discard_display_paths(number)

    def test_readiness_client_timeout_is_capped_by_remaining_startup_budget(self):
        real_run = subprocess.run
        attempts: list[float] = []

        def slow_client(argv, *args, **kwargs):
            if argv[0] != "xdpyinfo":
                return real_run(argv, *args, **kwargs)
            timeout = kwargs.get("timeout")
            attempts.append(1.0 if timeout is None else float(timeout))
            time.sleep(attempts[-1])
            raise subprocess.TimeoutExpired(argv, timeout or 0)

        started = time.monotonic()
        with mock.patch.object(probe.subprocess, "run", side_effect=slow_client):
            with self.assertRaises(RuntimeError):
                with probe.private_xvfb(timeout=0.25):
                    self.fail("display accepted despite a readiness client that never answered")
        elapsed = time.monotonic() - started
        self.assertTrue(attempts, "readiness client was never attempted")
        self.assertLessEqual(max(attempts), 0.3, "client timeout exceeded the remaining startup budget")
        self.assertLess(elapsed, 0.8, f"startup took {elapsed:.2f}s for a 0.25s budget")

    def test_process_and_credentials_cleanup_without_pillow(self):
        with probe.private_xvfb() as (_display, env, path, proc):
            self.assertIsNone(proc.returncode)
            authority = Path(env["XAUTHORITY"])
            self.assertTrue(authority.exists())
        # Only the context manager can have reaped the child here.
        self.assertIsNotNone(proc.returncode, "owned Xvfb must be reaped")
        self.assertFalse(path.exists(), "private directory must be removed")
        self.assertFalse(authority.exists(), "secret Xauthority file must be removed")

    def test_cleanup_when_owned_xvfb_is_killed(self):
        number = None
        try:
            with probe.private_xvfb() as (display, env, path, proc):
                number = int(display.removeprefix(":"))
                self.assertIsNone(proc.returncode)
                authority = Path(env["XAUTHORITY"])
                proc.kill()
            self.assertEqual(proc.returncode, -signal.SIGKILL, "crashed Xvfb must be reaped by the context")
            self.assertFalse(path.exists(), "crashed Xvfb's credentials must be cleaned up")
            self.assertFalse(authority.exists())
        finally:
            if number is not None:
                _discard_display_paths(number)

    def test_process_and_credentials_cleanup_on_body_failure(self):
        proc = None
        path = None
        with self.assertRaisesRegex(RuntimeError, "injected failure"):
            with probe.private_xvfb() as (_display, _env, directory, server):
                proc, path = server, directory
                raise RuntimeError("injected failure")
        self.assertIsNotNone(proc)
        assert proc is not None
        assert path is not None
        self.assertIsNotNone(proc.returncode, "owned Xvfb must be reaped on exception")
        self.assertFalse(path.exists(), "private directory must be removed on exception")

    def test_authentication_and_screenshot(self):
        with probe.private_xvfb(width=640, height=480) as (display, env, path, _proc):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            self.assertEqual(Path(env["XAUTHORITY"]).stat().st_mode & 0o777, 0o600)
            self.assertEqual(subprocess.run(["xdpyinfo"], env=env, capture_output=True, timeout=2).returncode, 0)
            # Prove a separate, incorrect cookie cannot inspect the display.
            bad = dict(env, XAUTHORITY=str(path / "not-a-cookie"))
            self.assertNotEqual(subprocess.run(["xdpyinfo"], env=bad, capture_output=True, timeout=2).returncode, 0)
            if not HAVE_PIL:
                self.skipTest("Pillow screenshot backend not installed")
            with tempfile.TemporaryDirectory() as out:
                file = Path(out) / "screen.png"
                self.assertEqual(probe.snapshot_png(env, file), (640, 480))
                self.assertTrue(file.is_file())
        self.assertFalse(path.exists(), "private runtime directory must be cleaned up")

    @unittest.skipUnless(HAVE_PIL, "Pillow is not installed")
    def test_capture_does_not_mutate_process_global_display_state(self):
        from PIL import ImageGrab

        keys = ("DISPLAY", "XAUTHORITY")
        with probe.private_xvfb(width=320, height=240) as (_display, env, _root, _proc):
            baseline = {key: os.environ.get(key) for key in keys}
            samples: list[dict[str, str | None]] = []
            stop = threading.Event()

            def watch():
                while not stop.is_set():
                    samples.append({key: os.environ.get(key) for key in keys})
                    time.sleep(0.005)

            real_grab = ImageGrab.grab

            def slow_grab(*args, **kwargs):
                # Widens the real overlap window of an in-process capture backend.
                time.sleep(0.4)
                return real_grab(*args, **kwargs)

            watcher = threading.Thread(target=watch, daemon=True)
            watcher.start()
            try:
                with tempfile.TemporaryDirectory() as out:
                    with mock.patch.object(ImageGrab, "grab", side_effect=slow_grab):
                        size = probe.snapshot_png(env, Path(out) / "capture.png")
            finally:
                stop.set()
                watcher.join(2)
            self.assertEqual(size, (320, 240))
            self.assertTrue(samples, "environment watcher never observed the capture")
            self.assertEqual(samples, [baseline] * len(samples), "capture mutated process-global DISPLAY/XAUTHORITY")
            self.assertEqual({key: os.environ.get(key) for key in keys}, baseline)

    @unittest.skipUnless(XTERM, "needs a sample GUI application (xterm)")
    def test_actual_gui_window_changes_capture(self):
        if not HAVE_PIL:
            self.skipTest("Pillow is not installed")
        from PIL import Image

        with probe.private_xvfb(width=640, height=480) as (_display, env, _root, _proc):
            with tempfile.TemporaryDirectory() as out:
                before = Path(out) / "before.png"
                after = Path(out) / "after.png"
                probe.snapshot_png(env, before)
                app = subprocess.Popen(
                    ["xterm", "-geometry", "40x10+20+20", "-bg", "white", "-fg", "black", "-e", "sh", "-c", "sleep 4"],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                try:
                    for _ in range(20):
                        time.sleep(0.1)
                        if app.poll() is not None:
                            self.fail("example GUI exited before screenshot")
                        probe.snapshot_png(env, after)
                        with Image.open(before) as first, Image.open(after) as second:
                            if first.convert("RGB").tobytes() != second.convert("RGB").tobytes():
                                break
                    else:
                        self.fail("X11 application did not produce any visible pixels")
                finally:
                    app.terminate()
                    app.wait(timeout=3)
                    if app.stderr:
                        app.stderr.close()

    @unittest.skipUnless(HAVE_PIL and XTERM, "needs Pillow and xterm")
    def test_two_gui_applications_render_concurrently_without_crossing_displays(self):
        from PIL import Image, ImageGrab

        barrier = threading.Barrier(2)
        real_grab = ImageGrab.grab

        def synchronised_grab(*args, **kwargs):
            # Forces both captures into the same instant, which is exactly when a
            # process-global DISPLAY/XAUTHORITY swap crosses sessions.
            try:
                barrier.wait(timeout=3)
            except threading.BrokenBarrierError:
                pass
            return real_grab(*args, **kwargs)

        with probe.private_xvfb(width=640, height=480) as (a, env_a, _root_a, proc_a):
            with probe.private_xvfb(width=640, height=480) as (b, env_b, _root_b, proc_b):
                self.assertNotEqual(a, b)
                apps = [self._start_xterm(env_a, "#0000ff"), self._start_xterm(env_b, "#ff0000")]
                try:
                    with tempfile.TemporaryDirectory() as out:
                        path_a = Path(out) / "display-a.png"
                        path_b = Path(out) / "display-b.png"
                        self._await_colour(env_a, path_a, (0, 0, 255))
                        self._await_colour(env_b, path_b, (255, 0, 0))
                        self.assertIsNone(proc_a.returncode)
                        self.assertIsNone(proc_b.returncode)
                        self.assertIsNone(apps[0].poll())
                        self.assertIsNone(apps[1].poll())
                        outcomes: dict[str, object] = {}

                        def capture(name, env, destination):
                            try:
                                outcomes[name] = probe.snapshot_png(env, destination)
                            except BaseException as exc:  # noqa: BLE001 - surfaced by assertion
                                outcomes[name] = exc

                        with mock.patch.object(ImageGrab, "grab", side_effect=synchronised_grab):
                            threads = [
                                threading.Thread(target=capture, args=("a", env_a, path_a)),
                                threading.Thread(target=capture, args=("b", env_b, path_b)),
                            ]
                            for thread in threads:
                                thread.start()
                            for thread in threads:
                                thread.join(30)
                        self.assertFalse(any(thread.is_alive() for thread in threads), "concurrent capture hung")
                        for name in ("a", "b"):
                            self.assertIsInstance(
                                outcomes.get(name), tuple, f"display {name} capture failed: {outcomes.get(name)!r}"
                            )
                        with Image.open(path_a) as image_a, Image.open(path_b) as image_b:
                            pixel_a = image_a.convert("RGB").getpixel(SAMPLE_POINT)
                            pixel_b = image_b.convert("RGB").getpixel(SAMPLE_POINT)
                        self.assertTrue(_colour_close(pixel_a, (0, 0, 255)), f"display A captured {pixel_a}")
                        self.assertTrue(_colour_close(pixel_b, (255, 0, 0)), f"display B captured {pixel_b}")
                finally:
                    for app in apps:
                        if app.poll() is None:
                            app.terminate()
                        try:
                            app.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            app.kill()
                            app.wait(timeout=3)

    @staticmethod
    def _start_xterm(env, background: str):
        return subprocess.Popen(
            [
                "xterm",
                "-geometry",
                "100x30+0+0",
                "-bg",
                background,
                "-fg",
                "black",
                "-e",
                "sh",
                "-c",
                "sleep 30",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _await_colour(self, env, path, colour) -> None:
        from PIL import Image

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            probe.snapshot_png(env, path)
            with Image.open(path) as image:
                if _colour_close(image.convert("RGB").getpixel(SAMPLE_POINT), colour):
                    return
            time.sleep(0.1)
        self.fail(f"expected window colour {colour} never rendered")

    def test_two_concurrent_displays_cannot_reuse_credentials(self):
        with probe.private_xvfb() as (a, env_a, root_a, _proc_a):
            with probe.private_xvfb() as (b, env_b, _, _proc_b):
                self.assertNotEqual(a, b)
                self.assertEqual(subprocess.run(["xdpyinfo"], env=env_a, capture_output=True, timeout=2).returncode, 0)
                self.assertEqual(subprocess.run(["xdpyinfo"], env=env_b, capture_output=True, timeout=2).returncode, 0)
                # Re-key B's real cookie to display A. This tests cookie rejection,
                # rather than merely failing because B's authority lacks an A entry.
                b_cookie_entries = (
                    subprocess.run(
                        ["xauth", "-f", env_b["XAUTHORITY"], "list", b],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=2,
                    )
                    .stdout.strip()
                    .splitlines()
                )
                self.assertEqual(len(b_cookie_entries), 1)
                b_cookie = b_cookie_entries[0].split()[-1]
                self.assertEqual(len(b_cookie), 32)
                crossed_authority = root_a / "crossed-auth"
                crossed_authority.touch(mode=0o600)
                crossed_authority.chmod(0o600)
                subprocess.run(
                    ["xauth", "-f", str(crossed_authority), "add", a, "MIT-MAGIC-COOKIE-1", b_cookie],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=2,
                )
                crossed = dict(env_a, XAUTHORITY=str(crossed_authority))
                self.assertNotEqual(
                    subprocess.run(["xdpyinfo"], env=crossed, capture_output=True, timeout=2).returncode, 0
                )


if __name__ == "__main__":
    unittest.main()
