#!/usr/bin/env python3
"""Run deterministic NAS fuzz/property tests with a reproducible seed and case count."""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=22001)
    parser.add_argument("--cases", type=int, default=2000)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.cases <= 10000:
        parser.error("--cases must be between 1 and 10000")
    env = os.environ.copy()
    env["NAS_FUZZ_SEED"] = str(args.seed)
    env["NAS_FUZZ_CASES"] = str(args.cases)
    command = [sys.executable, "-m", "unittest", "tests.test_fuzz_boundaries"]
    if args.verbose:
        command.append("-v")
    print(f"NAS fuzz seed={args.seed} cases={args.cases}")
    return subprocess.call(command, cwd=ROOT, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
