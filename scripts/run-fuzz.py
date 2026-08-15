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
import tempfile
import time
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
JS_FUZZ_ROOT = ROOT / "tests/js-fuzz"
FUZZ_RUN_GRACE_SECONDS = 1800
DEFAULT_FUZZ_WORKERS = 6
HYPOTHESIS_SUITES = {"boundaries", "custom-inputs", "properties", "stateful", "security"}


@dataclass(frozen=True)
class Suite:
    name: str
    command: tuple[str, ...]


def unittest_suite(name: str, module: str) -> Suite:
    return Suite(name, (sys.executable, "-m", "unittest", module, "-v"))


SUITES = {
    "boundaries": unittest_suite("boundaries", "tests.test_fuzz_boundaries"),
    "custom-inputs": unittest_suite("custom-inputs", "tests.test_fuzz_custom_inputs"),
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


def run_suite(suite: Suite, duration_seconds: float) -> tuple[str, int, str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.setdefault(
        "HYPOTHESIS_STORAGE_DIRECTORY",
        str(pathlib.Path(tempfile.gettempdir()) / f"nix-nas-hypothesis-{suite.name}"),
    )
    deadline = time.monotonic() + duration_seconds if duration_seconds else None
    runs = 0
    last_output = ""
    while True:
        prefix = ""
        if suite.name == "javascript":
            prepare_status, prefix = prepare_javascript_suite()
            if prepare_status:
                return suite.name, prepare_status, prefix
        # Allow a valid long-running property pass to finish after the window,
        # but bound a worker that never returns.
        timeout = None if deadline is None else max(1.0, deadline - time.monotonic()) + FUZZ_RUN_GRACE_SECONDS
        try:
            completed = subprocess.run(
                suite.command,
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            partial = error.output or ""
            if isinstance(partial, bytes):
                partial = partial.decode(errors="replace")
            return (
                suite.name,
                124,
                prefix
                + partial
                + f"smart fuzz: {suite.name} exceeded the requested {duration_seconds:.0f}s worker window\n",
            )
        runs += 1
        last_output = prefix + completed.stdout
        if completed.returncode:
            return suite.name, completed.returncode, last_output
        if deadline is None or time.monotonic() >= deadline:
            if duration_seconds:
                last_output += (
                    f"smart fuzz: {suite.name} completed {runs} run(s) in the requested {duration_seconds:.0f}s\n"
                )
            return suite.name, 0, last_output


def resolve_suites(selected_names: list[str], jobs: int, duration_seconds: float) -> list[Suite]:
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
    if duration_seconds:
        command.extend(["--duration-seconds", str(duration_seconds)])
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
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(DEFAULT_FUZZ_WORKERS, len(SUITES)),
        help="maximum parallel workers",
    )
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=0,
        help="repeat each selected suite until this many seconds have elapsed (local qualification only)",
    )
    args = parser.parse_args()
    if not 1 <= args.jobs <= len(SUITES):
        parser.error(f"--jobs must be from 1 through {len(SUITES)}")
    if args.duration_seconds < 0:
        parser.error("--duration-seconds must be zero or greater")

    selected_names = list(dict.fromkeys(args.suite or SUITES.keys()))
    try:
        selected = resolve_suites(selected_names, args.jobs, args.duration_seconds)
    except RuntimeError as exc:
        print(f"smart fuzz setup failed: {exc}", file=sys.stderr)
        return 2

    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.jobs, len(selected))) as executor:
        futures = [executor.submit(run_suite, suite, args.duration_seconds) for suite in selected]
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
