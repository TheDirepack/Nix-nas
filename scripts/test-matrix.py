#!/usr/bin/env python3
"""Run the NAS verification matrix with bounded stages and JSON evidence."""

from __future__ import annotations

import argparse
import json
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
class Stage:
    name: str
    command: tuple[str, ...]
    timeout: int
    requires: tuple[str, ...] = ()
    required_paths: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()


def stage_catalog() -> dict[str, Stage]:
    return {
        "source": Stage(
            "source",
            ("bash", "scripts/preflight.sh"),
            900,
            requires=("bash", "python3"),
            env=(("NAS_PREFLIGHT_SKIP_FUZZ", "1"),),
        ),
        "security": Stage(
            "security",
            (sys.executable, "scripts/run-security-tests.py"),
            300,
            requires=("python3", "node"),
        ),
        "fuzz": Stage(
            "fuzz",
            (sys.executable, "scripts/run-fuzz.py"),
            900,
            requires=("python3", "nix", "npm"),
        ),
        "nix-config": Stage(
            "nix-config",
            ("bash", "scripts/nix-config-matrix.sh"),
            1200,
            requires=("bash", "nix"),
        ),
        "browser": Stage(
            "browser",
            ("npm", "--prefix", "cockpit", "run", "test:browser"),
            1200,
            requires=("npm",),
            required_paths=(
                "cockpit/package-lock.json",
                "cockpit/dist/index.js",
                "cockpit/dist/index.css",
                "cockpit/node_modules/@playwright/test/package.json",
            ),
        ),
        "native": Stage(
            "native",
            ("bash", "scripts/qemu-test.sh", "native"),
            7200,
            requires=("bash", "nix"),
        ),
        "installer": Stage(
            "installer",
            ("bash", "scripts/qemu-test.sh", "installer"),
            10800,
            requires=("bash", "qemu-system-x86_64", "qemu-img", "expect", "bsdtar", "ssh", "curl"),
        ),
    }


def missing_reason(stage: Stage) -> str | None:
    missing_commands = [name for name in stage.requires if shutil.which(name) is None]
    if missing_commands:
        return "missing command(s): " + ", ".join(missing_commands)
    missing_paths = [name for name in stage.required_paths if not (ROOT / name).is_file()]
    if missing_paths:
        return "missing reviewed artifact(s): " + ", ".join(missing_paths)
    return None


def run_bounded(command: Sequence[str], *, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
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


def run_stage(
    stage: Stage, *, timeout_override: int | None = None, require_complete_source: bool = False
) -> dict[str, object]:
    reason = missing_reason(stage)
    if reason:
        return {"name": stage.name, "status": "skipped", "reason": reason}
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(dict(stage.env))
    if require_complete_source and stage.name == "source":
        env["NAS_PREFLIGHT_REQUIRE_COMPLETE"] = "1"
    timeout = timeout_override or stage.timeout
    started = time.monotonic()
    try:
        completed = run_bounded(stage.command, env=env, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {
            "name": stage.name,
            "status": "failed",
            "reason": f"exceeded {timeout}s",
            "durationSeconds": round(time.monotonic() - started, 3),
            "stdoutTail": (exc.stdout or "")[-8000:] if isinstance(exc.stdout, str) else "",
            "stderrTail": (exc.stderr or "")[-8000:] if isinstance(exc.stderr, str) else "",
        }
    duration = round(time.monotonic() - started, 3)
    result: dict[str, object] = {
        "name": stage.name,
        "status": "passed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "durationSeconds": duration,
    }
    if completed.returncode != 0:
        result["stdoutTail"] = completed.stdout[-8000:]
        result["stderrTail"] = completed.stderr[-8000:]
    return result


def print_result(result: dict[str, object]) -> None:
    status = str(result["status"]).upper()
    name = result["name"]
    detail = ""
    if result.get("reason"):
        detail = f": {result['reason']}"
    elif result.get("durationSeconds") is not None:
        detail = f" ({result['durationSeconds']}s)"
    print(f"{status} {name}{detail}")
    if result["status"] == "failed":
        if result.get("stdoutTail"):
            print("--- stdout tail ---", file=sys.stderr)
            print(result["stdoutTail"], file=sys.stderr)
        if result.get("stderrTail"):
            print("--- stderr tail ---", file=sys.stderr)
            print(result["stderrTail"], file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        nargs="?",
        default="fast",
        choices=("fast", "source", "security", "fuzz", "nix-config", "browser", "native", "installer", "all", "list"),
    )
    parser.add_argument("--timeout", type=int, help="override the timeout for each selected stage")
    parser.add_argument("--report", type=pathlib.Path, help="write JSON stage evidence to this path")
    parser.add_argument("--require-all", action="store_true", help="treat an unavailable selected stage as failure")
    args = parser.parse_args()
    if args.timeout is not None and not 1 <= args.timeout <= 86400:
        parser.error("--timeout must be from 1 through 86400 seconds")

    catalog = stage_catalog()
    if args.mode == "list":
        for name, stage in catalog.items():
            availability = missing_reason(stage) or "available"
            print(f"{name:10} {availability}")
        return 0
    if args.mode == "fast":
        selected = ("source", "security")
    elif args.mode == "all":
        selected = tuple(catalog)
    else:
        selected = (args.mode,)

    results: list[dict[str, object]] = []
    for name in selected:
        result = run_stage(
            catalog[name],
            timeout_override=args.timeout,
            require_complete_source=args.require_all,
        )
        if result["status"] == "skipped" and args.require_all:
            result["status"] = "failed"
            result["reason"] = "required stage unavailable: " + str(result.get("reason", "unknown reason"))
        results.append(result)
        print_result(result)
        if result["status"] == "failed":
            break

    payload = {
        "schemaVersion": 2,
        "mode": args.mode,
        "results": results,
        "ok": all(row["status"] in {"passed", "skipped"} for row in results)
        and not (args.require_all and any(row["status"] == "skipped" for row in results)),
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
