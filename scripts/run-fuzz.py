#!/usr/bin/env python3
"""Run the organized smart-fuzz suites, in parallel by default.

Structured Python inputs are generated and shrunk by Hypothesis.  This runner is
only orchestration; it deliberately contains no home-grown mutation logic.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import pathlib
import subprocess
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Suite:
    name: str
    command: tuple[str, ...]


SUITES = {
    "properties": Suite(
        "properties",
        (
            "nix",
            "develop",
            ".#test",
            "-c",
            "./scripts/run-unit-tests.py",
            "--jobs",
            "1",
            "--pattern",
            "test_property_invariants.py",
        ),
    ),
    "security": Suite(
        "security",
        (
            "nix",
            "develop",
            ".#test",
            "-c",
            "./scripts/run-unit-tests.py",
            "--jobs",
            "1",
            "--pattern",
            "test_secret_security_fuzz.py",
        ),
    ),
    "executables": Suite(
        "executables",
        (sys.executable, "scripts/fuzz-executables.py"),
    ),
}


def run_suite(suite: Suite) -> tuple[str, int, str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        suite.command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return suite.name, completed.returncode, completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        action="append",
        choices=sorted(SUITES),
        help="suite to run; repeat to select several (default: all)",
    )
    parser.add_argument("--jobs", type=int, default=len(SUITES), help="maximum parallel suites")
    args = parser.parse_args()
    if not 1 <= args.jobs <= len(SUITES):
        parser.error(f"--jobs must be from 1 through {len(SUITES)}")

    selected_names = list(dict.fromkeys(args.suite or SUITES.keys()))
    selected = [SUITES[name] for name in selected_names]
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.jobs, len(selected))) as executor:
        futures = [executor.submit(run_suite, suite) for suite in selected]
        for future in concurrent.futures.as_completed(futures):
            name, returncode, output = future.result()
            if output:
                print(f"===== smart fuzz: {name} =====")
                print(output, end="" if output.endswith("\n") else "\n")
            if returncode:
                failures += 1
                print(f"smart fuzz failed: {name} (exit {returncode})", file=sys.stderr)
            else:
                print(f"smart fuzz ok: {name}")

    if failures:
        print(f"smart fuzz failed: {failures}/{len(selected)} suite(s)", file=sys.stderr)
        return 1
    print(f"smart fuzz complete: {len(selected)} suite(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
