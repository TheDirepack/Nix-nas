#!/usr/bin/env python3
"""Adversarially exercise every repository-owned maintenance executable.

Installed appliance commands have a separate disposable-VM fuzz strategy in
``tests/vm/adversarial-installed.py``. This harness covers source-tree tools and
refuses to silently skip a newly added executable.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "tests/custom-script-contracts.json"
# The fixed sentinel must match literal attack payloads so marker creation is detectable.
MARKER = pathlib.Path("/tmp/nas-source-fuzz-pwned")  # nosec B108
PAYLOADS = (
    "../../../../etc/shadow",
    ";touch /tmp/nas-source-fuzz-pwned",
    "$(touch /tmp/nas-source-fuzz-pwned)",
    "' OR 1=1 --",
    "<script>globalThis.pwned=1</script>",
    "bad\r\nInjected: yes",
    "--",
    "A" * 4096,
    "--help;id",
    "../../../../root/.ssh/authorized_keys",
    "admin'/**/OR/**/'1'='1",
    "<svg/onload=globalThis.pwned=1>",
    "javascript:globalThis.pwned=1",
    "http://169.254.169.254/latest/meta-data/",
    "\u202eadmin",
    "🧪" * 256,
)


def command_for(relative: str) -> list[str]:
    path = ROOT / relative
    suffix = path.suffix
    if suffix == ".py":
        return [sys.executable, str(path)]
    if suffix in {".js", ".cjs", ".mjs"}:
        return ["node", str(path)]
    if suffix == ".sh":
        return ["bash", str(path)]
    raise RuntimeError(f"no source fuzz runner for {relative}")


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


def execute(name: str, strategy: str, payload: str, temporary: pathlib.Path) -> None:
    base = command_for(name)
    if strategy == "hostile-argv":
        run([*base, payload])
    elif strategy == "unknown-option":
        run([*base, "--fuzz-" + payload], env={"NAS_QEMU_CACHE_DIR": str(temporary / "qemu")})
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
        raise RuntimeError(f"unknown source fuzz strategy {strategy!r} for {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=3)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x534352495054)
    args = parser.parse_args()
    if not 1 <= args.cases <= 100:
        parser.error("--cases must be from 1 through 100")

    strategies = inventory()
    if not strategies:
        raise SystemExit("no source executable fuzz strategies are registered")
    MARKER.unlink(missing_ok=True)
    rng = random.Random(args.seed)
    with tempfile.TemporaryDirectory() as temporary_name:
        temporary = pathlib.Path(temporary_name)
        for name, strategy in sorted(strategies.items()):
            # Validators that do not expose a meaningful repeated input stream are run
            # once with hostile argv; their data parsers are fuzzed by scripts/fuzz.py
            # and focused tests. Repeating a whole-repository validator only multiplies
            # scan time without exploring a different boundary.
            single_pass = {
                "aggregate-contract",
                "hostile-argv",
                "preflight-local",
                "shell-parse",
                "source-check",
                "syntax-contract",
            }
            iterations = 1 if strategy in single_pass else args.cases
            for _ in range(iterations):
                execute(name, strategy, rng.choice(PAYLOADS), temporary)
            print(f"executable fuzz ok: {name}: {strategy}: {iterations} case(s)")
    print(json.dumps({"ok": True, "executables": len(strategies), "seed": args.seed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
