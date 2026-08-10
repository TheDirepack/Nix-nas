#!/usr/bin/env python3
"""Run structured parser/boundary fuzzing through Hypothesis.

The previous implementation contained a project-local random mutation engine.
Hypothesis now owns generation, targeting, shrinking, and reproduction; this
script remains as the stable CLI used by CI and developer tooling.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # Compatibility with historical CI invocations. Hypothesis controls its own
    # generation budget; these options are accepted so old callers fail cleanly
    # while the workflow is migrated to the organized suite runner.
    parser.add_argument("--cases", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--seed", type=lambda value: int(value, 0), help=argparse.SUPPRESS)
    parser.add_argument("--crash-dir", type=pathlib.Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.cases is not None and args.cases < 1:
        parser.error("--cases must be positive")

    if importlib.util.find_spec("hypothesis") is None:
        print(
            "Hypothesis is required for structured parser fuzzing; run this command inside `nix develop .#test`.",
            file=sys.stderr,
        )
        return 2

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [
        sys.executable,
        "-m",
        "unittest",
        "tests.test_fuzz_boundaries",
        "-v",
    ]
    return subprocess.call(command, cwd=ROOT, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
