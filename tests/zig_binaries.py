"""Locate or build the Zig KeePass binaries for black-box tests.

`NAS_ZIG_HARNESS_BIN_DIR` / `NAS_ZIG_RELEASE_BIN_DIR` point at prebuilt
binaries (CI, Nix). Otherwise the binaries are built once per checkout into
`tmp/zig-*` under an exclusive lock, which keeps parallel test workers from
racing on the install step.
"""

from __future__ import annotations

import fcntl
import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIG_PROJECT = ROOT / "zig"
_cache: dict[str, pathlib.Path] = {}


def _zig() -> str:
    explicit = os.environ.get("NAS_ZIG")
    if explicit:
        return explicit
    found = shutil.which("zig")
    if found is None:
        raise RuntimeError("zig 0.17 is required for the KeePass black-box tests (use `nix develop .#test`)")
    return found


def _build(kind: str, flags: list[str]) -> pathlib.Path:
    override = os.environ.get(f"NAS_ZIG_{kind.upper()}_BIN_DIR")
    if override:
        return pathlib.Path(override)
    if kind in _cache:
        return _cache[kind]
    prefix = ROOT / "tmp" / f"zig-{kind}"
    prefix.mkdir(parents=True, exist_ok=True)
    with open(prefix / ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        subprocess.run(
            [_zig(), "build", *flags, "--prefix", str(prefix)],
            cwd=ZIG_PROJECT,
            check=True,
            stdout=subprocess.DEVNULL,
            timeout=900,
        )
    _cache[kind] = prefix / "bin"
    return _cache[kind]


def harness_bin_dir() -> pathlib.Path:
    """Binaries with comptime test hooks (relocatable paths, non-root unlock API)."""
    return _build("harness", ["-Dtest-harness=true", "-Drelease=true"])


def release_bin_dir() -> pathlib.Path:
    """Production binaries: no test hooks compiled in."""
    return _build("release", ["-Drelease=true"])
