#!/usr/bin/env python3
"""Run organized smart-fuzz and adversarial suites in parallel.

Hypothesis owns structured generation, targeting, shrinking, and reproduction.
This runner enters the pinned Nix test environment once, then fans independent
target classes out in parallel. It contains no project-local mutation engine.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Suite:
    name: str
    command: tuple[str, ...]


def unittest_suite(name: str, module: str) -> Suite:
    return Suite(name, (sys.executable, "-m", "unittest", module, "-v"))


SUITES = {
    "boundaries": unittest_suite("boundaries", "tests.test_fuzz_boundaries"),
    "properties": unittest_suite("properties", "tests.test_property_invariants"),
    "stateful": unittest_suite("stateful", "tests.slow_managed_service_stateful"),
    "security": unittest_suite("security", "tests.test_secret_security_fuzz"),
    "executable-contracts": Suite(
        "executable-contracts",
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


def enter_test_environment(argv: list[str]) -> int | None:
    """Re-exec once through the pinned test shell when Hypothesis is unavailable."""

    if importlib.util.find_spec("hypothesis") is not None:
        return None
    nix = shutil.which("nix")
    if nix is None:
        print(
            "Hypothesis is required for smart fuzzing and Nix is unavailable; run inside `nix develop .#test`.",
            file=sys.stderr,
        )
        return 2
    command = [nix, "develop", ".#test", "-c", "python3", "scripts/run-fuzz.py", *argv]
    return subprocess.call(command, cwd=ROOT, env=os.environ.copy())


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

    forwarded: list[str] = []
    for suite in args.suite or []:
        forwarded.extend(["--suite", suite])
    forwarded.extend(["--jobs", str(args.jobs)])
    reexec_status = enter_test_environment(forwarded)
    if reexec_status is not None:
        return reexec_status

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
