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
ALLOWLIST_ZERO = frozenset()
# This file is also run by the dedicated Caddy CI job after installing the real
# Caddy binary. Generic source/non-root jobs may lack that external executable,
# so an all-skipped result there is allowed only for this explicit capability
# test. Every other discovered test file must execute at least one real test.
ALLOWLIST_ALL_SKIPPED = frozenset({"test_service_caddy_validate.py"})
FAILURES_RE = re.compile(r"failures=(\d+)")
ERRORS_RE = re.compile(r"errors=(\d+)")
SKIPPED_RE = re.compile(r"skipped=(\d+)")
EXPECTED_RE = re.compile(r"expected failures=(\d+)")
UNEXPECTED_RE = re.compile(r"unexpected successes=(\d+)")
RESULT_RE = re.compile(r"^(OK|FAILED)(?: \(([^)]+)\))?\s*$", re.MULTILINE)
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
    # Host is never NixOS (no /run/nas-state tmpfs, no nas-* system users, no
    # /var/lib/nas-llama-swap). Make the fast suite hermetic so `pytest` on
    # ubuntu-24.04 matches the VM gate (see tests/README.md "Where tests run").
    # Tests that truly need a NixOS closure should be marked `requires_vm`.
    env.setdefault("NAS_STATE_ALLOW_UNPRIVILEGED", "1")
    # Per-run temp roots so parallel jobs and successive runs do not collide.
    # Use a single temp dir for the whole harness run (cleaned up on exit).
    _hermetic_tmp = pathlib.Path(tempfile.mkdtemp(prefix="nas-test-hermetic-"))
    # State runtime root (for nas_state, operation_lock)
    if "NAS_STATE_RUNTIME_ROOT" not in env:
        try:
            os.makedirs("/run/nas-state", exist_ok=False)
            os.rmdir("/run/nas-state")
        except OSError:
            env["NAS_STATE_RUNTIME_ROOT"] = str(_hermetic_tmp / "nas-state")
    # Secret roots for cockpit_api / ai_config
    if "NAS_SECRET_ROOT" not in env:
        env["NAS_SECRET_ROOT"] = str(_hermetic_tmp / "nas-secrets")
    if "NAS_LLAMA_SWAP_CONFIG" not in env:
        # Create a minimal valid llama-swap config so load_config() does not fail
        # with FileNotFoundError on host. Tests that need specific config will
        # override this via mock or temp path.
        _llama_dir = _hermetic_tmp / "nas-llama-swap"
        _llama_dir.mkdir(parents=True, exist_ok=True)
        _llama_cfg = _llama_dir / "config.yaml"
        if not _llama_cfg.exists():
            _llama_cfg.write_text("models: {}\npeers: {}\nselectors: {}\n", encoding="utf-8")
        env["NAS_LLAMA_SWAP_CONFIG"] = str(_llama_cfg)
    # State rollback / journal paths (for nas_state, operation_journal)
    if "NAS_STATE_ROLLBACK_ROOT" not in env:
        try:
            os.makedirs("/var/lib/nas-state", exist_ok=False)
            os.rmdir("/var/lib/nas-state")
        except OSError:
            env["NAS_STATE_ROLLBACK_ROOT"] = str(_hermetic_tmp / "nas-state-rollback")
    if "NAS_STATE_RESTORE_JOURNAL" not in env:
        # Use the same hermetic state dir for the journal so it is writable
        _state_journal_dir = pathlib.Path(
            env.get("NAS_STATE_ROLLBACK_ROOT", str(_hermetic_tmp / "nas-state-rollback"))
        )
        env["NAS_STATE_RESTORE_JOURNAL"] = str(_state_journal_dir / "restore-operation.json")
    # Feature control / setup / operation roots (all under /var/lib or /run on host)
    _hermetic_map = {
        "NAS_FEATURE_STATE": str(_hermetic_tmp / "nas-control" / "settings.json"),
        "NAS_FEATURE_JOURNAL": str(_hermetic_tmp / "nas-control" / "transaction.json"),
        "NAS_FEATURE_LAST_GOOD": str(_hermetic_tmp / "nas-control" / "settings.last-good.json"),
        "NAS_FEATURE_RUNTIME": str(_hermetic_tmp / "nas-control" / "on-demand.json"),
        "NAS_FEATURE_LOCK": str(_hermetic_tmp / "nas-control" / "feature-control.lock"),
        "NAS_FEATURE_CATALOG": str(_hermetic_tmp / "nas-control" / "features.json"),
        "NAS_SETUP_STATE": str(_hermetic_tmp / "nas-setup" / "state.json"),
        "NAS_SETUP_JOURNAL": str(_hermetic_tmp / "nas-setup" / "first-run-journal.json"),
        "NAS_SETUP_STATE_ROOT": str(_hermetic_tmp / "nas-setup"),
        "NAS_FEATURE_STATE_ROOT": str(_hermetic_tmp / "nas-control"),
        "NAS_OPERATION_ROOT": str(_hermetic_tmp / "nas-operations"),
        "NAS_OPERATION_GROUP": "users",  # host fallback when nas-operations group missing
        "NAS_COCKPIT_SUPERUSER_BYPASS": "1",  # allow --help without root in tests
    }
    for key, val in _hermetic_map.items():
        env.setdefault(key, val)
    # Ensure secret and state root subdirs exist so lstat() checks pass
    try:
        pathlib.Path(env["NAS_SECRET_ROOT"]).mkdir(parents=True, exist_ok=True)
        (pathlib.Path(env["NAS_SECRET_ROOT"]) / "ai").mkdir(parents=True, exist_ok=True)
        # Ready marker for tests that check /run/nas-secrets/ready
        (pathlib.Path(env["NAS_SECRET_ROOT"]) / "ready").touch(exist_ok=True)
        for key in [
            "NAS_STATE_ROLLBACK_ROOT",
            "NAS_FEATURE_STATE",
            "NAS_FEATURE_JOURNAL",
            "NAS_FEATURE_LAST_GOOD",
            "NAS_SETUP_STATE",
            "NAS_SETUP_JOURNAL",
            "NAS_OPERATION_ROOT",
        ]:
            if key in env:
                p = pathlib.Path(env[key])
                # If it's a file path, ensure parent exists; if dir, ensure dir exists
                target = p.parent if p.suffix else p
                target.mkdir(parents=True, exist_ok=True)
        # Seed minimal feature catalog and setup state so load_state() does not fail
        _feat_catalog = pathlib.Path(env["NAS_FEATURE_CATALOG"])
        if not _feat_catalog.exists():
            _feat_catalog.parent.mkdir(parents=True, exist_ok=True)
            _feat_catalog.write_text('{"features": {}, "groups": {}}', encoding="utf-8")
        for pkey in ["NAS_FEATURE_STATE", "NAS_SETUP_STATE"]:
            p = pathlib.Path(env[pkey])
            if not p.exists():
                p.write_text("{}", encoding="utf-8")
    except OSError:
        pass
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

    total_ran = 0
    total_passed = 0
    total_failed = 0
    total_errored = 0
    total_skipped = 0
    total_expected = 0
    total_unexpected = 0
    started = time.monotonic()

    def _parse_counts(output: str) -> tuple[int, int, int, int, int, int]:
        ran = 0
        m = RAN_RE.search(output or "")
        if m:
            ran = int(m.group(1))
        failures = 0
        errors = 0
        skipped = 0
        expected = 0
        unexpected = 0
        rm = RESULT_RE.search(output or "")
        detail = rm.group(2) if rm and rm.group(2) else ""
        if detail:
            pairs = {k.strip(): v for k, v in re.findall(r"([a-z ]+)=\s*(\d+)", detail)}
            if "failures" in pairs:
                failures = int(pairs["failures"])
            if "errors" in pairs:
                errors = int(pairs["errors"])
            if "skipped" in pairs:
                skipped = int(pairs["skipped"])
            if "expected failures" in pairs:
                expected = int(pairs["expected failures"])
            if "unexpected successes" in pairs:
                unexpected = int(pairs["unexpected successes"])
        return ran, failures, errors, skipped, expected, unexpected

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
        nonlocal total_ran, total_passed, total_failed, total_errored, total_skipped, total_expected, total_unexpected
        path, completed, elapsed, count, output = result
        relative = path.relative_to(ROOT).as_posix()
        ran, fail_c, err_c, skip_c, exp_c, unexp_c = _parse_counts(output or "")
        passed_c = ran - fail_c - err_c - skip_c - exp_c - unexp_c
        if passed_c < 0:
            passed_c = 0
        if completed is None:
            total_ran += ran
            total_failed += fail_c
            total_errored += err_c
            total_skipped += skip_c
            total_expected += exp_c
            total_unexpected += unexp_c
            failures.append((path, f"exceeded {args.timeout}s\n{(output or '')[-8000:]}"))
            print(f"FAIL {relative}: exceeded {args.timeout}s", file=sys.stderr)
            return
        if completed.returncode != 0:
            total_ran += ran
            total_failed += fail_c
            total_errored += err_c
            total_skipped += skip_c
            total_expected += exp_c
            total_unexpected += unexp_c
            total_passed += passed_c
            failures.append((path, f"rc={completed.returncode}\n{(output or '')[-16000:]}"))
            print(f"FAIL {relative}: rc={completed.returncode} after {elapsed:.1f}s", file=sys.stderr)
            return
        if ran == 0 and path.name not in ALLOWLIST_ZERO:
            total_ran += ran
            total_skipped += skip_c
            failures.append((path, "no tests discovered\n" + (output or "")[-16000:]))
            print(f"FAIL {relative}: no tests discovered after {elapsed:.1f}s", file=sys.stderr)
            return
        if ran > 0 and skip_c == ran and path.name not in ALLOWLIST_ALL_SKIPPED:
            total_ran += ran
            total_skipped += skip_c
            failures.append((path, "all discovered tests were skipped\n" + (output or "")[-16000:]))
            print(f"FAIL {relative}: all {ran} discovered tests were skipped after {elapsed:.1f}s", file=sys.stderr)
            return
        total_ran += ran
        total_failed += fail_c
        total_errored += err_c
        total_skipped += skip_c
        total_expected += exp_c
        total_unexpected += unexp_c
        total_passed += passed_c
        detail_parts = []
        if skip_c:
            detail_parts.append(f"skipped={skip_c}")
        if exp_c:
            detail_parts.append(f"expected failures={exp_c}")
        if unexp_c:
            detail_parts.append(f"unexpected successes={unexp_c}")
        if fail_c:
            detail_parts.append(f"failures={fail_c}")
        if err_c:
            detail_parts.append(f"errors={err_c}")
        detail_str = f" ({', '.join(detail_parts)})" if detail_parts else ""
        print(f"PASS {relative}: {passed_c} test(s) passed, {ran} ran{detail_str}, {elapsed:.1f}s")

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
        print(
            f"unit suite failed: {total_passed} tests passed, {total_failed} failed, {total_errored} errored, "
            f"{total_skipped} skipped, {total_expected} expectedFailures, {total_unexpected} unexpectedSuccesses, "
            f"{total_ran} ran across {len(files)} files with {args.jobs} worker(s) in {time.monotonic() - started:.1f}s",
            file=sys.stderr,
        )
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
        f"unit suite passed: {total_passed} tests across {len(files)} files "
        f"with {args.jobs} worker(s) in {time.monotonic() - started:.1f}s "
        f"(passed={total_passed}, failed={total_failed}, errored={total_errored}, "
        f"skipped={total_skipped}, expectedFailures={total_expected}, "
        f"unexpectedSuccesses={total_unexpected}, ran={total_ran})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
