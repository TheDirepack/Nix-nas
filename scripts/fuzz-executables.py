#!/usr/bin/env python3
"""Validate adversarial contracts for repository-owned executable surfaces.

This is intentionally not a mutation fuzzer.  Input parsers are covered by
Hypothesis property tests; this layer checks whole-process behavior that only
exists at the executable boundary (no shell injection, no signal death, no
tracebacks, syntax/source/preflight contracts).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "tests/custom-script-contracts.json"
MARKER = pathlib.Path("/tmp/nas-source-fuzz-pwned")  # nosec B108
SHELL_INJECTION_SENTINEL = ";touch /tmp/nas-source-fuzz-pwned"
INVALID_OPTION_SENTINEL = "--nas-invalid-option=../not-a-real-value"


def command_for(relative: str) -> list[str]:
    path = ROOT / relative
    suffix = path.suffix
    if suffix == ".py":
        return [sys.executable, str(path)]
    if suffix in {".js", ".cjs", ".mjs"}:
        return ["node", str(path)]
    if suffix == ".sh":
        return ["bash", str(path)]
    raise RuntimeError(f"no source contract runner for {relative}")


def run(
    command: list[str], *, env: dict[str, str] | None = None, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        merged.update(env)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=merged,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode < 0:
        raise RuntimeError(f"process died by signal: {command!r}: {completed.returncode}")
    if "Traceback (most recent call last)" in completed.stderr:
        raise RuntimeError(f"unhandled Python traceback: {command!r}: {completed.stderr[-2000:]}")
    if MARKER.exists():
        raise RuntimeError(f"argument injection created marker: {command!r}")
    return completed


def inventory() -> dict[str, str]:
    data = json.loads(INVENTORY.read_text(encoding="utf-8"))
    result: dict[str, str] = {}
    for name, row in data["executables"].items():
        strategy = row.get("sourceFuzzStrategy")
        if isinstance(strategy, str) and strategy:
            result[name] = strategy
    return result


def execute(name: str, strategy: str, temporary: pathlib.Path) -> None:
    base = command_for(name)
    if strategy == "hostile-argv":
        run([*base, SHELL_INJECTION_SENTINEL])
    elif strategy == "unknown-option":
        run([*base, INVALID_OPTION_SENTINEL], env={"NAS_QEMU_CACHE_DIR": str(temporary / "qemu")})
    elif strategy == "shell-parse":
        result = run(["bash", "-n", str(ROOT / name)])
        if result.returncode != 0:
            raise RuntimeError(f"shell parser rejected {name}: {result.stderr}")
    elif strategy == "source-check":
        result = run([*base, "--check-source"])
        if result.returncode != 0:
            raise RuntimeError(f"source check failed for {name}: {result.stderr}")
    elif strategy == "syntax-contract":
        result = run(["node", "--check", str(ROOT / name)])
        if result.returncode != 0:
            raise RuntimeError(f"JavaScript syntax check failed for {name}: {result.stderr}")
    elif strategy == "aggregate-contract":
        source = (ROOT / name).read_text(encoding="utf-8")
        if "run-unit-tests.py" not in source:
            raise RuntimeError(f"aggregate test wrapper contract drifted: {name}")
    elif strategy == "preflight-local":
        result = run(
            base,
            env={"NAS_PREFLIGHT_SKIP_TESTS": "1", "NAS_PREFLIGHT_SKIP_FUZZ": "1"},
            timeout=90,
        )
        if result.returncode != 0:
            raise RuntimeError(f"local preflight failed: {result.stdout[-2000:]}{result.stderr[-2000:]}")
    else:
        raise RuntimeError(f"unknown source executable contract {strategy!r} for {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # Kept temporarily for callers from the old mutation-fuzz workflow.
    parser.add_argument("--cases", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--seed", type=lambda value: int(value, 0), help=argparse.SUPPRESS)
    parser.parse_args()

    strategies = inventory()
    if not strategies:
        raise SystemExit("no source executable adversarial contracts are registered")
    MARKER.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory() as temporary_name:
        temporary = pathlib.Path(temporary_name)
        for name, strategy in sorted(strategies.items()):
            execute(name, strategy, temporary)
            print(f"executable contract ok: {name}: {strategy}")
    print(json.dumps({"ok": True, "executables": len(strategies)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
