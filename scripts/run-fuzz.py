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


def resolve_suites(selected_names: list[str], jobs: int) -> list[Suite]:
    """Resolve one Nix worker group for Hypothesis when needed."""

    selected_hypothesis = [name for name in selected_names if name in HYPOTHESIS_SUITES]
    direct_names = [name for name in selected_names if name not in HYPOTHESIS_SUITES]
    resolved = [SUITES[name] for name in direct_names]
    if not selected_hypothesis:
        return resolved
    if importlib.util.find_spec("hypothesis") is not None:
        resolved.extend(SUITES[name] for name in selected_hypothesis)
        return resolved

    nix = shutil.which("nix")
    if nix is None:
        missing = ", ".join(selected_hypothesis)
        raise RuntimeError(f"Hypothesis suites require Nix or an installed Hypothesis package: {missing}")
    command = [nix, "develop", ".#test", "-c", "python3", "scripts/run-fuzz.py"]
    for name in selected_hypothesis:
        command.extend(["--suite", name])
    command.extend(["--jobs", str(min(jobs, len(selected_hypothesis)))])
    resolved.append(Suite("hypothesis", tuple(command)))
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        action="append",
        choices=sorted(SUITES),
        help="suite to run; repeat to select several (default: all)",
    )
    parser.add_argument("--jobs", type=int, default=len(SUITES), help="maximum parallel workers")
    args = parser.parse_args()
    if not 1 <= args.jobs <= len(SUITES):
        parser.error(f"--jobs must be from 1 through {len(SUITES)}")

    selected_names = list(dict.fromkeys(args.suite or SUITES.keys()))
    try:
        selected = resolve_suites(selected_names, args.jobs)
    except RuntimeError as exc:
        print(f"smart fuzz setup failed: {exc}", file=sys.stderr)
        return 2

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
        print(f"smart fuzz failed: {failures}/{len(selected)} worker(s)", file=sys.stderr)
        return 1
    print(f"smart fuzz complete: {len(selected_names)} suite(s) across {len(selected)} worker(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
