#!/usr/bin/env python3
"""Run the deterministic source-level security test tier with bounded subprocesses."""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Sequence

ROOT = pathlib.Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Check:
    name: str
    command: tuple[str, ...]
    requires: tuple[str, ...] = ()


CHECKS = (
    Check("static-security-scan", (sys.executable, "scripts/security-static-scan.py")),
    Check(
        "python-security-tests",
        (
            sys.executable,
            "-m",
            "unittest",
            "tests.test_security_surface",
            "tests.test_adversarial_security",
            "tests.test_secret_transaction",
            "tests.test_secret_transaction_followup",
            "tests.test_secret_security",
            "tests.test_keepass_fail_closed",
            "tests.test_secret_journal_security",
            "tests.test_ai_secret_transaction",
            "tests.test_secret_subprocess_redaction",
            "tests.test_logging",
            "-v",
        ),
    ),
    Check("javascript-security-tests", ("node", "--test", "tests/js/security.test.mjs"), requires=("node",)),
    Check("browser-security-spec-syntax", ("node", "--check", "cockpit/e2e/ui-security.spec.mjs"), requires=("node",)),
)


def run(command: Sequence[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    argv = list(command)
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr) from exc
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=180, help="deadline for each security check")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be from 1 through 3600 seconds")

    started = time.monotonic()
    for check in CHECKS:
        missing = [name for name in check.requires if shutil.which(name) is None]
        if missing:
            print(f"security check unavailable: {check.name}: missing {', '.join(missing)}", file=sys.stderr)
            return 2
        try:
            result = run(check.command, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            print(f"security check timed out: {check.name} after {args.timeout}s", file=sys.stderr)
            return 1
        if result.returncode != 0:
            print(f"security check failed: {check.name}", file=sys.stderr)
            if result.stdout:
                print(result.stdout[-16000:], file=sys.stderr)
            if result.stderr:
                print(result.stderr[-16000:], file=sys.stderr)
            return 1
        print(f"security check ok: {check.name}")

    print(f"security tier ok: {len(CHECKS)} checks in {time.monotonic() - started:.2f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
