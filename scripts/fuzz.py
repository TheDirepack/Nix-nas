#!/usr/bin/env python3
"""Compatibility entry point for the structured boundary Hypothesis suite."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # Historical callers supplied mutation-engine controls. They are accepted
    # only so old invocations migrate cleanly; Hypothesis owns its own search
    # budget, shrinking, and replay semantics.
    parser.add_argument("--cases", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--seed", type=lambda value: int(value, 0), help=argparse.SUPPRESS)
    parser.add_argument("--crash-dir", type=pathlib.Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.cases is not None and args.cases < 1:
        parser.error("--cases must be positive")

    return subprocess.call(
        [sys.executable, "scripts/run-fuzz.py", "--suite", "boundaries", "--jobs", "1"],
        cwd=ROOT,
    )


if __name__ == "__main__":
    raise SystemExit(main())
