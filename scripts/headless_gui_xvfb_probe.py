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
import select
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

_DISPLAY_SOCKET_DIR = Path("/tmp/.X11-unix")
_DISPLAY_LOCK_DIR = Path("/tmp")
# Readiness uses the upstream client unchanged; a single client attempt is
# capped by whatever remains of the outer startup budget.
_CLIENT_TIMEOUT = 1.0
_CAPTURE_TIMEOUT = 10.0
# Pillow's X11 backend has no cancellation API, so capture runs in a child
# process that the parent can bound and kill without touching its own env.
_CAPTURE_SCRIPT = """
import json
import sys

from PIL import ImageGrab

image = ImageGrab.grab()
image.save(sys.argv[1], "PNG")
print(json.dumps({"size": list(image.size)}))
"""


def _require(*names: str) -> None:
    absent = [name for name in names if shutil.which(name) is None]
    if absent:
        raise RuntimeError("missing test-only dependencies: " + ", ".join(absent))


def _display_paths(number: int) -> tuple[Path, Path]:
    return _DISPLAY_SOCKET_DIR / f"X{number}", _DISPLAY_LOCK_DIR / f".X{number}-lock"


def _preexisting_displays() -> set[int]:
    """Display numbers already claimed before this session spawns a server."""
    numbers: set[int] = set()
    try:
        for entry in _DISPLAY_SOCKET_DIR.iterdir():
            suffix = entry.name.removeprefix("X")
            if entry.name != suffix and suffix.isdigit():
                numbers.add(int(suffix))
    except OSError:
        pass
    for entry in _DISPLAY_LOCK_DIR.glob(".X*-lock"):
        suffix = entry.name.removeprefix(".X").removesuffix("-lock")
        if suffix.isdigit():
            numbers.add(int(suffix))
    return numbers


def _socket_is_live(path: Path) -> bool:
    """True when a process still accepts connections on this display socket."""
    if not path.exists():
        return False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(0.2)
        try:
            client.connect(str(path))
        except (ConnectionRefusedError, FileNotFoundError, NotADirectoryError):
            return False
        except OSError:
            # Permission and protocol errors are not proof that the socket is dead.
            return True
        return True


def _remove_owned_display_artifacts(number: int, pid: int, preexisting: set[int]) -> None:
    """Remove only artifacts this session created, after its server is reaped."""
    if number in preexisting:
        return
    socket_path, lock_path = _display_paths(number)
    try:
        lock_owner = int(lock_path.read_text(encoding="ascii").strip())
    except (FileNotFoundError, ValueError, OSError):
        lock_owner = None
    if lock_owner is not None:
        # A lock naming another process means that display now belongs to it.
        if lock_owner != pid:
            return
        lock_path.unlink(missing_ok=True)
    if not _socket_is_live(socket_path):
        socket_path.unlink(missing_ok=True)


def _log_tail(path: Path, limit: int = 400) -> str:
    try:
        return path.read_bytes()[-limit:].decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _read_allocated_display(read_fd: int, proc: subprocess.Popen, deadline: float) -> int | None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if select.select([read_fd], [], [], min(remaining, 0.1))[0]:
            data = os.read(read_fd, 64)
            if not data:
                return None
            text = data.decode("ascii", "replace").strip().splitlines()[0]
            return int(text) if text.isdigit() else None
        if proc.poll() is not None:
            if select.select([read_fd], [], [], 0)[0]:
                text = os.read(read_fd, 64).decode("ascii", "replace").strip()
                return int(text) if text.isdigit() else None
            return None


def _wait_for_owned_socket(number: int, proc: subprocess.Popen, deadline: float, preexisting: set[int]) -> None:
    """Require Xvfb's own `-displayfd` choice and socket before yielding it."""
    display = f":{number}"
    if number in preexisting:
        raise RuntimeError(f"Xvfb reported pre-existing display {display}")
    socket_path, _lock_path = _display_paths(number)
    while not socket_path.exists():
        if proc.poll() is not None:
            raise RuntimeError(f"Xvfb exited before creating the socket for {display}")
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Xvfb did not create the socket for {display} in time")
        time.sleep(0.02)
    info = socket_path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError(f"display socket for {display} is not owned by this session")


def _wait_for_readiness(display: str, env: dict[str, str], proc: subprocess.Popen, deadline: float, log: Path) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"Xvfb failed readiness for {display}: {_log_tail(log)}")
        if proc.poll() is not None:
            raise RuntimeError(f"Xvfb exited before readiness for {display}: {_log_tail(log)}")
        try:
            probe = subprocess.run(
                ["xdpyinfo"],
                env=env,
                capture_output=True,
                timeout=min(_CLIENT_TIMEOUT, remaining),
                check=False,
            )
        except subprocess.TimeoutExpired:
            # A slow client is not a failed display until the outer deadline.
            continue
        if probe.returncode == 0:
            return
        time.sleep(min(0.08, max(0.0, deadline - time.monotonic())))


@contextmanager
def private_xvfb(*, width: int = 800, height: int = 600, depth: int = 24, timeout: float = 6.0):
    """Yield (display, subprocess env, private directory, Xvfb process); clean up on exit.

    Xvfb chooses and reports its own display through `-displayfd`, so the probe
    never adopts a pre-existing server. The Xauthority file exists before the
    server starts and the per-display cookie is added before any client
    connects. No -ac, host X11 socket mounts, TCP listener, or privileged device
    access.
    """
    if width < 64 or height < 64 or depth not in (16, 24, 32):
        raise ValueError("unsupported smoke-test screen geometry")
    _require("Xvfb", "xauth", "xdpyinfo")
    deadline = time.monotonic() + timeout

    with tempfile.TemporaryDirectory(prefix="v2-xvfb-probe-") as root:
        private_dir = Path(root)
        os.chmod(private_dir, 0o700)
        preexisting = _preexisting_displays()
        authority = private_dir / "Xauthority"
        authority.touch(mode=0o600)
        os.chmod(authority, 0o600)
        log_path = private_dir / "xvfb.log"
        read_fd: int | None = None
        write_fd: int | None = None
        number: int | None = None
        proc: subprocess.Popen | None = None
        try:
            read_fd, write_fd = os.pipe()
            with open(log_path, "wb") as log_file:
                proc = subprocess.Popen(
                    [
                        "Xvfb",
                        "-displayfd",
                        str(write_fd),
                        "-screen",
                        "0",
                        f"{width}x{height}x{depth}",
                        "-nolisten",
                        "tcp",
                        "-auth",
                        str(authority),
                        "-noreset",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=log_file,
                    pass_fds=(write_fd,),
                    env=dict(os.environ),
                )
            os.close(write_fd)
            write_fd = None
            number = _read_allocated_display(read_fd, proc, deadline)
            os.close(read_fd)
            read_fd = None
            if number is None:
                raise RuntimeError("Xvfb did not allocate a display: " + _log_tail(log_path))
            display = f":{number}"
            _wait_for_owned_socket(number, proc, deadline, preexisting)

            if time.monotonic() >= deadline:
                raise RuntimeError(f"Xvfb startup overran its deadline before readiness for {display}")
            cookie = secrets.token_hex(16)
            try:
                result = subprocess.run(
                    ["xauth", "-f", str(authority), "-"],
                    input=f"add {display} MIT-MAGIC-COOKIE-1 {cookie}\n",
                    capture_output=True,
                    text=True,
                    timeout=max(0.1, min(3.0, deadline - time.monotonic())),
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("xauth did not store the private cookie in time") from exc
            if result.returncode:
                raise RuntimeError("xauth rejected private cookie: " + result.stderr.strip())

            env = dict(os.environ, DISPLAY=display, XAUTHORITY=str(authority))
            _wait_for_readiness(display, env, proc, deadline, log_path)
            yield display, env, private_dir, proc
        finally:
            if read_fd is not None:
                os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
            if proc is not None:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                if number is not None:
                    _remove_owned_display_artifacts(number, proc.pid, preexisting)
            authority.unlink(missing_ok=True)


def snapshot_png(env: dict[str, str], path: Path, *, timeout: float = _CAPTURE_TIMEOUT) -> tuple[int, int]:
    """Capture through Pillow's X11 backend in a bounded child process.

    The child receives the session's DISPLAY/XAUTHORITY, so concurrent captures
    never mutate or restore the caller's process environment.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-c", _CAPTURE_SCRIPT, str(path)],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"screenshot capture exceeded {timeout} seconds") from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()[-400:]
        raise RuntimeError("screenshot capture failed: " + detail)
    try:
        size = json.loads(result.stdout.decode("utf-8", "replace"))["size"]
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("screenshot capture returned no image size") from exc
    return int(size[0]), int(size[1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screenshot", type=Path, help="save a screenshot during this disposable probe")
    args = parser.parse_args()
    with private_xvfb() as (display, env, private_dir, _proc):
        status: dict[str, object] = {
            "display": display,
            "isolated_cookie": True,
            "private_dir_mode": oct(private_dir.stat().st_mode & 0o777),
            "tcp_listener": False,
        }
        if args.screenshot:
            size = snapshot_png(env, args.screenshot)
            status["screenshot_size"] = list(size)
        print(json.dumps(status, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
