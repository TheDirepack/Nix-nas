#!/usr/bin/env python3
"""Enforce per-package statement coverage for go/ from unit and black-box runs.

Go unit tests and the Python black-box suites (which exercise the real
binaries built with -cover) both write counters; the floors apply to the
merged profile.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = "github.com/TheDirepack/Nix-nas/go"
BLACKBOX_SUITES = (
    "tests.test_nas_secrets_blackbox",
    "tests.test_unlock_api",
    "tests.test_zfs_key_staging",
    "tests.test_setup",
    "tests.test_v2_setup_runtime_coverage",
)
FLOORS = {
    "cmd/nas-keepass-setup": 72.0,
    "cmd/nas-secrets": 60.0,
    "cmd/nas-unlock-api": 55.0,
    "internal/cmdexec": 85.0,
    "internal/config": 67.0,
    "internal/keepass": 83.0,
    "internal/lineio": 80.0,
    "internal/nassecrets": 75.0,
    "internal/secret": 81.0,
    "internal/setupkp": 68.0,
    "internal/syspath": 80.0,
    "internal/txn": 80.0,
    "internal/unlockapi": 88.0,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as raw:
        unit = pathlib.Path(raw) / "unit"
        blackbox = pathlib.Path(raw) / "blackbox"
        unit.mkdir()
        blackbox.mkdir()
        env = {**os.environ, "GOTOOLCHAIN": "local", "GOFLAGS": os.environ.get("GOFLAGS", "-mod=mod")}
        subprocess.run(
            [args.go, "test", "-count=1", "-cover", "-coverpkg=./...", "./...", "-args", f"-test.gocoverdir={unit}"],
            cwd=ROOT / "go",
            env=env,
            check=True,
        )
        subprocess.run(
            [sys.executable, "-m", "unittest", *BLACKBOX_SUITES],
            cwd=ROOT,
            env={
                **{key: value for key, value in env.items() if key not in {"NAS_KEEPASS_SETUP_BIN", "NAS_GO_BIN_DIR"}},
                "GOCOVERDIR": str(blackbox),
                "NAS_REQUIRE_GO_BINARIES": "1",
            },
            check=True,
        )
        report = subprocess.run(
            [args.go, "tool", "covdata", "percent", f"-i={unit},{blackbox}"],
            cwd=ROOT / "go",
            env=env,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    measured: dict[str, float] = {}
    for line in report.splitlines():
        match = re.match(rf"\s*{re.escape(MODULE)}/(\S+)\s+coverage:\s+([0-9.]+)%", line)
        if match:
            measured[match.group(1)] = float(match.group(2))
    failed = False
    for package, floor in sorted(FLOORS.items()):
        value = measured.get(package)
        status = "ok" if value is not None and value >= floor else "FAIL"
        failed |= status == "FAIL"
        print(f"{status:4} {package:28} {value if value is not None else 0:5.1f}% (floor {floor:.0f}%)")
    unknown = sorted(set(measured) - set(FLOORS))
    if unknown:
        print(f"FAIL packages without a coverage floor: {', '.join(unknown)}")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
