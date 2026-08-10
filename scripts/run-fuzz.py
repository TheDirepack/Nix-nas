#!/usr/bin/env python3
"""Run organized smart-fuzz and adversarial suites in parallel.

Hypothesis owns structured Python generation, targeting, shrinking, and replay;
fast-check does the same for JavaScript properties. This runner only orchestrates
independent target classes and contains no project-local mutation engine.
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
JS_FUZZ_ROOT = ROOT / "tests/js-fuzz"
HYPOTHESIS_SUITES = {"boundaries", "properties", "stateful", "security"}


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
    "javascript": Suite("javascript", ("npm", "--prefix", "tests/js-fuzz", "test")),
    "executable-contracts": Suite(
        "executable-contracts",
        (sys.executable, "scripts/fuzz-executables.py"),
    ),
}


def prepare_javascript_suite() -> tuple[int, str]:
    npm = shutil.which("npm")
    if npm is None:
        return 2, "npm is required for the fast-check JavaScript property suite\n"
    installed = JS_FUZZ_ROOT / "node_modules/fast-check/package.json"
    if installed.is_file():
        return 0, ""
    completed = subprocess.run(
        [npm, "--prefix", "tests/js-fuzz", "ci", "--no-audit", "--no-fund"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return completed.returncode, completed.stdout


def run_suite(suite: Suite) -> tuple[str, int, str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    prefix = ""
    if suite.name == "javascript":
        prepare_status, prefix = prepare_javascript_suite()
        if prepare_status:
            return suite.name, prepare_status, prefix
    completed = subprocess.run(
        suite.command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return suite.name, completed.returncode, prefix + completed.stdout


def enter_test_environment(selected_names: list[str], argv: list[str]) -> int | None:
    """Re-exec once through the pinned test shell only for Hypothesis suites."""

    if not HYPOTHESIS_SUITES.intersection(selected_names):
        return None
    if importlib.util.find_spec("hypothesis") is not None:
        return None
    nix = shutil.which("nix")
    if nix is None:
        print(
            "Hypothesis suites need the pinned Nix test environment; Nix is unavailable.",
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

    selected_names = list(dict.fromkeys(args.suite or SUITES.keys()))
    forwarded: list[str] = []
    for suite in args.suite or []:
        forwarded.extend(["--suite", suite])
    forwarded.extend(["--jobs", str(args.jobs)])
    reexec_status = enter_test_environment(selected_names, forwarded)
    if reexec_status is not None:
        return reexec_status

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
