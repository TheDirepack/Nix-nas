#!/usr/bin/env python3
"""Run Python test files in isolated subprocesses with bounded deadlines."""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
RAN_RE = re.compile(r"Ran (\d+) tests? in")
SERIAL_TEST_FILES = frozenset(
    {
        "test_cli_surfaces.py",
        "test_contract_tooling.py",
        "test_maintainer_core.py",
        "test_maintainer_matrix.py",
        "test_maintainer_release.py",
        "test_script_inventory.py",
    }
)


def _kill_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _process_group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def run(command: list[str], *, timeout: int, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    # Use files rather than capture pipes. A leaked grandchild can inherit a pipe and
    # keep communicate() waiting forever after the actual test process has exited.
    with (
        tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stdout_file,
        tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stderr_file,
    ):
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _kill_process_group(process.pid)
            process.wait()
            stdout_file.seek(0)
            stderr_file.seek(0)
            raise subprocess.TimeoutExpired(
                command, timeout, output=stdout_file.read(), stderr=stderr_file.read()
            ) from exc

        # Give normal short-lived helpers a small reap window. Any remaining member of
        # the isolated process group is a test resource leak and is forcibly removed.
        for _ in range(5):
            if not _process_group_exists(process.pid):
                break
            time.sleep(0.02)
        leaked = _process_group_exists(process.pid)
        if leaked:
            _kill_process_group(process.pid)

        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read()
        stderr = stderr_file.read()
        returncode = process.returncode
        if leaked:
            stderr += "\n[test harness detected and killed leaked descendant process(es)]\n"
            if returncode == 0:
                returncode = 125
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def coverage_cleanup() -> None:
    # Coverage data files are `.coverage` and `.coverage.<suffix>`.  Do not use
    # `.coverage*` here: that also matches and deletes the committed `.coveragerc`.
    candidates = [ROOT / ".coverage", *ROOT.glob(".coverage.*")]
    for path in candidates:
        if path.is_file():
            path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=180, help="maximum seconds for one test file")
    parser.add_argument("--coverage", metavar="REPORT", help="write combined coverage.py JSON to REPORT")
    parser.add_argument("--pattern", default="test_*.py", help="test filename glob")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="NAME",
        help="exclude an exact test filename; repeat for multiple integration files",
    )
    parser.add_argument("--quiet", action="store_true", help="print only per-file status and failures")
    parser.add_argument("--jobs", type=int, default=1, help="number of isolated test files to run concurrently")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be from 1 through 3600 seconds")
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be from 1 through 32")

    excluded = set(args.exclude)
    files = sorted(path for path in TESTS.glob(args.pattern) if path.name not in excluded)
    if not files:
        parser.error(f"no test files matched {args.pattern!r}")

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    python_path = [str(ROOT / "services"), str(ROOT / "tests")]
    if env.get("PYTHONPATH"):
        python_path.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_path)

    if args.coverage:
        try:
            subprocess.run(
                [sys.executable, "-m", "coverage", "--version"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                check=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            print("coverage.py is required for --coverage", file=sys.stderr)
            return 2
        coverage_cleanup()

    total_tests = 0
    started = time.monotonic()

    def command_for(unittest_command: list[str]) -> list[str]:
        if args.coverage:
            return [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--parallel-mode",
                "--branch",
                "--source=services",
                *unittest_command,
            ]
        return [sys.executable, *unittest_command]

    def run_file(
        path: pathlib.Path,
    ) -> tuple[pathlib.Path, subprocess.CompletedProcess[str] | None, float, int, str | None]:
        unittest_command = [
            "-m",
            "unittest",
            "discover",
            "-s",
            str(TESTS),
            "-p",
            path.name,
        ]
        if not args.quiet:
            unittest_command.append("-v")
        command = command_for(unittest_command)
        file_started = time.monotonic()
        try:
            completed = run(command, timeout=args.timeout, env=env)
        except subprocess.TimeoutExpired as exc:
            output = ""
            if isinstance(exc.stdout, str):
                output += exc.stdout
            if isinstance(exc.stderr, str):
                output += exc.stderr
            return path, None, time.monotonic() - file_started, 0, output
        output = completed.stdout + completed.stderr
        match = RAN_RE.search(output)
        count = int(match.group(1)) if match else 0
        return path, completed, time.monotonic() - file_started, count, output

    failures: list[tuple[pathlib.Path, str]] = []

    def record(result: tuple[pathlib.Path, subprocess.CompletedProcess[str] | None, float, int, str | None]) -> None:
        nonlocal total_tests
        path, completed, elapsed, count, output = result
        relative = path.relative_to(ROOT).as_posix()
        if completed is None:
            failures.append((path, f"exceeded {args.timeout}s\n{(output or '')[-8000:]}"))
            print(f"FAIL {relative}: exceeded {args.timeout}s", file=sys.stderr)
            return
        if completed.returncode != 0:
            failures.append((path, f"rc={completed.returncode}\n{(output or '')[-16000:]}"))
            print(f"FAIL {relative}: rc={completed.returncode} after {elapsed:.1f}s", file=sys.stderr)
            return
        total_tests += count
        print(f"PASS {relative}: {count} test(s), {elapsed:.1f}s")

    serial_files = [path for path in files if path.name in SERIAL_TEST_FILES]
    parallel_files = [path for path in files if path.name not in SERIAL_TEST_FILES]
    if parallel_files:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = [pool.submit(run_file, path) for path in parallel_files]
            for future in concurrent.futures.as_completed(futures):
                record(future.result())
    # Repository/package validator tests intentionally execute alone. They create clean
    # copies and run heavyweight release tooling; concurrent copies only add timeout
    # noise and can make resource pressure look like a product regression.
    for path in serial_files:
        record(run_file(path))

    if failures:
        for path, detail in sorted(failures, key=lambda item: item[0].name):
            print(f"--- {path.relative_to(ROOT).as_posix()} ---", file=sys.stderr)
            print(detail, file=sys.stderr)
        return 124 if any("exceeded" in detail for _, detail in failures) else 1

    if args.coverage:
        report = pathlib.Path(args.coverage)
        combine = subprocess.run(
            [sys.executable, "-m", "coverage", "combine", "--keep"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if combine.returncode != 0:
            print(combine.stdout + combine.stderr, file=sys.stderr)
            return combine.returncode
        exported = subprocess.run(
            [sys.executable, "-m", "coverage", "json", "-o", str(report)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if exported.returncode != 0:
            print(exported.stdout + exported.stderr, file=sys.stderr)
            return exported.returncode
        print(exported.stdout.strip())

    print(
        f"unit suite passed: {total_tests} tests across {len(files)} files "
        f"with {args.jobs} worker(s) in {time.monotonic() - started:.1f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
