"""Build the Go KeePass binaries once per test process for black-box tests.

`NAS_GO_BIN_DIR` points at prebuilt binaries (Nix or CI). Otherwise the
module under go/ is built with the local toolchain; the `nasblackbox`
variant of nas-unlock-api may run unprivileged and admit an explicit peer.
Without a toolchain the tests skip, unless `NAS_REQUIRE_GO_BINARIES=1`.
"""

from __future__ import annotations

import atexit
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "go"
_lock = threading.Lock()
_built: dict[str, pathlib.Path] = {}
_workdir: pathlib.Path | None = None


def _go() -> str | None:
    return os.environ.get("NAS_GO") or shutil.which("go")


def binary(name: str, *, blackbox: bool = False) -> pathlib.Path:
    """Return the path of cmd/<name>, building it on first use."""
    global _workdir
    key = f"{name}{'-blackbox' if blackbox else ''}"
    prebuilt = os.environ.get("NAS_GO_BIN_DIR")
    if prebuilt:
        path = pathlib.Path(prebuilt) / key
        if not path.is_file():
            if os.environ.get("NAS_REQUIRE_GO_BINARIES") == "1":
                raise AssertionError(f"{path} is missing")
            raise unittest.SkipTest(f"{path} is not available")
        return path
    with _lock:
        if key in _built:
            return _built[key]
        go = _go()
        if go is None:
            if os.environ.get("NAS_REQUIRE_GO_BINARIES") == "1":
                raise AssertionError("the Go toolchain is required for KeePass black-box tests")
            raise unittest.SkipTest("the Go toolchain is unavailable")
        if _workdir is None:
            _workdir = pathlib.Path(tempfile.mkdtemp(prefix="nas-go-bin-"))
            atexit.register(shutil.rmtree, _workdir, True)
        output = _workdir / key
        command = [go, "build", "-trimpath", "-o", str(output)]
        if blackbox:
            command += ["-tags", "nasblackbox"]
        command.append(f"./cmd/{name}")
        env = {**os.environ, "CGO_ENABLED": "0", "GOFLAGS": os.environ.get("GOFLAGS", "-mod=mod")}
        result = subprocess.run(command, cwd=MODULE, env=env, capture_output=True, text=True, check=False, timeout=600)
        if result.returncode != 0:
            raise AssertionError(f"go build {name} failed:\n{result.stderr}")
        _built[key] = output
        return output
