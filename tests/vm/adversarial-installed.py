#!/usr/bin/env python3
"""Adversarial checks against NAS-owned commands in an installed disposable VM."""

from __future__ import annotations

import json
import hashlib
import os
import pathlib
import subprocess

ROOT = pathlib.Path("/var/lib/nas-test/repo")
INVENTORIES = (
    ROOT / "tests/custom-script-contracts.json",
    ROOT / "tests/custom-script-contracts-v2.json",
)
MARKER = pathlib.Path("/tmp/nas-installed-fuzz-pwned")
PAYLOADS = (
    "../escape",
    "bad\r\nInjected: yes",
    "A" * 2048,
)
DELEGATED_STRATEGIES = {"protocol-system-test", "system-lifecycle", "disposable-zfs-lifecycle"}

# Strategies live in the reviewed executable inventories so adding a new
# installed command without an adversarial classification fails preflight.
# Destructive storage commands are fuzzed only inside disposable ZFS tests.


def run(command: list[str], *, allowed: set[int], diagnostic: str) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)
    if completed.returncode not in allowed:
        raise RuntimeError(
            f"unexpected exit {completed.returncode} for {command!r}:\nstdout={completed.stdout}\nstderr={completed.stderr}"
        )
    if "Traceback (most recent call last)" in completed.stderr:
        raise RuntimeError(f"unhandled traceback for {command!r}: {completed.stderr}")
    if diagnostic.lower() not in (completed.stdout + completed.stderr).lower():
        raise RuntimeError(f"wrong rejection category for {command!r}: {completed.stderr}")
    if MARKER.exists():
        raise RuntimeError(f"command payload created injection marker: {command!r}")
    return completed


def authority_snapshot() -> dict[str, str]:
    paths = (
        pathlib.Path("/var/lib/nas-control/services.yaml"),
        pathlib.Path("/var/lib/nas-setup/local-administrator.json"),
    )
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def inventory_strategies() -> dict[str, str]:
    strategies: dict[str, str] = {}
    for path in INVENTORIES:
        raw = json.loads(path.read_text(encoding="utf-8"))
        for name, row in raw["executables"].items():
            strategy = row.get("fuzzStrategy")
            if isinstance(strategy, str) and strategy:
                strategies[name] = strategy
    return strategies


def main() -> int:
    MARKER.unlink(missing_ok=True)
    strategies = inventory_strategies()
    if not strategies:
        raise SystemExit("installed fuzz inventory contains no strategies")

    commands: set[str] = set()
    for name in sorted(strategies):
        if pathlib.Path(f"/run/current-system/sw/bin/{name}").exists() or shutil_which(name):
            commands.add(name)
        else:
            raise RuntimeError(f"installed custom command is missing: {name}")

    executed: set[str] = set()
    delegated: set[str] = set()
    payloads = PAYLOADS[:1] if os.environ.get("NAS_INSTALLED_FUZZ_SMOKE") == "1" else PAYLOADS
    before = authority_snapshot()
    for name, strategy in sorted(strategies.items()):
        if name not in commands:
            continue
        if strategy == "unknown-argv":
            subprocess.run([name, "--help"], check=True, text=True, capture_output=True, timeout=20)
            for payload in payloads:
                run([name, "--fuzz-" + payload], allowed={2}, diagnostic="usage")
        elif strategy == "unknown-verb":
            for payload in payloads:
                run([name, "fuzz-" + payload], allowed={2}, diagnostic="Usage: nas-secrets")
        elif strategy == "feature-id":
            subprocess.run([name, "document"], check=True, text=True, capture_output=True, timeout=20)
            for payload in payloads:
                run([name, "set", payload, "always"], allowed={1}, diagnostic="Unknown Managed Services V2 service")
        elif strategy == "username":
            for payload in payloads:
                run(
                    [name, "account", "apply", "--username", payload, "--disabled"],
                    allowed={1},
                    diagnostic="Account username is unsafe",
                )
        elif strategy == "output-path":
            for payload in payloads:
                # Relative hostile paths must be rejected before any secret is read or file is written.
                run([name, payload], allowed={2}, diagnostic="output path must be absolute")
        elif strategy == "alert-header":
            run([name, "bad\r\nX-NAS-Fuzz: injected", "must not send"], allowed={2}, diagnostic="one line")
            run([name, "x" * 201, "must not send"], allowed={2}, diagnostic="one line")
        elif strategy == "disabled-state":
            run([name], allowed={1}, diagnostic="Enable nas.power.ups")
        elif strategy in DELEGATED_STRATEGIES:
            # Covered by guest-test.sh / encrypted-guest-test.sh with real service/storage state.
            delegated.add(name)
            continue
        else:
            raise RuntimeError(f"unknown fuzz strategy for {name}: {strategy}")
        executed.add(name)
        if authority_snapshot() != before:
            raise RuntimeError(f"rejected command changed authority: {name}")

    print(
        json.dumps(
            {
                "ok": True,
                "smoke": os.environ.get("NAS_INSTALLED_FUZZ_SMOKE") == "1",
                "commands": len(executed),
                "discovered": len(commands),
                "executed": sorted(executed),
                "delegated": sorted(delegated),
                "skipped": [],
                "strategies": strategies,
            },
            sort_keys=True,
        )
    )
    return 0


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


if __name__ == "__main__":
    raise SystemExit(main())
