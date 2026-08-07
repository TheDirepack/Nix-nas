#!/usr/bin/env python3
"""Run all source fuzz layers with one seed/case contract."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=2000)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x4E41533232)
    args = parser.parse_args()
    if not 1 <= args.cases <= 100_000:
        parser.error("--cases must be from 1 through 100000")
    executable_cases = max(1, min(20, args.cases // 1000 or 1))
    commands = [
        [sys.executable, "scripts/fuzz.py", "--cases", str(args.cases), "--seed", str(args.seed)],
        [sys.executable, "scripts/run-fuzz.py", "--cases", str(min(args.cases, 10000)), "--seed", str(args.seed)],
        [
            sys.executable,
            "scripts/fuzz-executables.py",
            "--cases",
            str(executable_cases),
            "--seed",
            str(args.seed ^ 0x534352495054),
        ],
    ]
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode != 0:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
