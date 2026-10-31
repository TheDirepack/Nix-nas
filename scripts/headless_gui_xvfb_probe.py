"""Disposable Xvfb isolation smoke-test; not a V2 runtime/controller.

This developer probe deliberately exercises an actual display session. It is not
an application launcher, management API, or production V2 implementation.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time


def _require(*names: str) -> None:
    absent = [name for name in names if shutil.which(name) is None]
    if absent:
        raise RuntimeError("missing test-only dependencies: " + ", ".join(absent))


@contextmanager
def private_xvfb(*, width: int = 800, height: int = 600, depth: int = 24, timeout: float = 6.0):
    """Yield (display, subprocess env, private directory); clean up on exit.

    Each attempt uses a random display number. Xvfb's own socket/lock protocol
    decides whether it is free, so an existing display is never stopped.
    The Xauthority cookie is created *before* the server starts. No -ac,
    host X11 socket mounts, TCP listener, or privileged device access.
    """
    if width < 64 or height < 64 or depth not in (16, 24, 32):
        raise ValueError("unsupported smoke-test screen geometry")
    _require("Xvfb", "xauth", "xdpyinfo")

    with tempfile.TemporaryDirectory(prefix="v2-xvfb-probe-") as root:
        private_dir = Path(root)
        os.chmod(private_dir, 0o700)
        for _ in range(12):
            number = 1000 + secrets.randbelow(20000)
            display = f":{number}"
            authority = private_dir / f"auth-{number}"
            authority.touch(mode=0o600)
            os.chmod(authority, 0o600)
            cookie = secrets.token_hex(16)
            result = subprocess.run(
                ["xauth", "-f", str(authority), "-"],
                input=f"add {display} MIT-MAGIC-COOKIE-1 {cookie}\n",
                capture_output=True, text=True, timeout=3, check=False,
            )
            if result.returncode:
                raise RuntimeError("xauth rejected private cookie: " + result.stderr.strip())
            env = dict(os.environ, DISPLAY=display, XAUTHORITY=str(authority))
            proc = subprocess.Popen(
                ["Xvfb", display, "-screen", "0", f"{width}x{height}x{depth}",
                 "-nolisten", "tcp", "-auth", str(authority), "-noreset"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, env=env,
            )
            try:
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        # Another process could have acquired this display first.
                        break
                    probe = subprocess.run(
                        ["xdpyinfo"], env=env, capture_output=True, timeout=1, check=False,
                    )
                    if probe.returncode == 0:
                        yield display, env, private_dir
                        return
                    time.sleep(0.08)
                if proc.poll() is None:
                    raise RuntimeError(f"Xvfb failed readiness for {display}")
                # With the display chosen randomly, a rare collision should retry.
                err = proc.stderr.read(4096).decode("utf-8", "replace") if proc.stderr else ""
                if "already active" not in err and "server is already running" not in err:
                    raise RuntimeError("Xvfb exited before readiness: " + err.strip()[:400])
            finally:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                if proc.stderr:
                    proc.stderr.close()
                authority.unlink(missing_ok=True)
        raise RuntimeError("could not allocate a private Xvfb display after 12 attempts")


def snapshot_png(env: dict[str, str], path: Path) -> tuple[int, int]:
    """Capture via Pillow's X11 backend, with the session's scoped auth cookie."""
    from PIL import ImageGrab

    old_display = os.environ.get("DISPLAY")
    old_auth = os.environ.get("XAUTHORITY")
    try:
        os.environ["DISPLAY"] = env["DISPLAY"]
        os.environ["XAUTHORITY"] = env["XAUTHORITY"]
        img = ImageGrab.grab(xdisplay=env["DISPLAY"])
        img.save(path, "PNG")
        return img.size
    finally:
        for key, value in (("DISPLAY", old_display), ("XAUTHORITY", old_auth)):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screenshot", type=Path, help="save a screenshot during this disposable probe")
    args = parser.parse_args()
    with private_xvfb() as (display, env, private_dir):
        status: dict[str, object] = {"display": display, "isolated_cookie": True,
                                     "private_dir_mode": oct(private_dir.stat().st_mode & 0o777),
                                     "tcp_listener": False}
        if args.screenshot:
            size = snapshot_png(env, args.screenshot)
            status["screenshot_size"] = list(size)
        print(json.dumps(status, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
