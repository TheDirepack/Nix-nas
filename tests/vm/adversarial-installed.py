#!/usr/bin/env python3
"""Adversarial checks against NAS-owned commands in an installed disposable VM."""

from __future__ import annotations

import json
import pathlib
import subprocess

ROOT = pathlib.Path("/var/lib/nas-test/repo")
INVENTORY = ROOT / "tests/custom-script-contracts.json"
MARKER = pathlib.Path("/tmp/nas-installed-fuzz-pwned")
PAYLOADS = (
    "../etc/shadow",
    ";touch /tmp/nas-installed-fuzz-pwned",
    "$(touch /tmp/nas-installed-fuzz-pwned)",
    "<img src=x onerror=alert(1)>",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "admin'/**/OR/**/'1'='1",
    "bad\r\nInjected: yes",
    "../../../../root/.ssh/authorized_keys",
    "javascript:globalThis.pwned=1",
    "<svg/onload=globalThis.pwned=1>",
    "http://169.254.169.254/latest/meta-data/",
    "\u202eadmin",
    "A" * 2048,
)

# Strategies live in the reviewed executable inventory so adding a new installed
# command without an adversarial classification fails preflight. Destructive storage
# commands are fuzzed only inside the disposable ZFS lifecycle tests.


def run(command: list[str], *, allowed: set[int] | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)
    if allowed is None:
        allowed = set(range(1, 256))
    if completed.returncode not in allowed:
        raise RuntimeError(
            f"unexpected exit {completed.returncode} for {command!r}:\nstdout={completed.stdout}\nstderr={completed.stderr}"
        )
    if "Traceback (most recent call last)" in completed.stderr:
        raise RuntimeError(f"unhandled traceback for {command!r}: {completed.stderr}")
    if MARKER.exists():
        raise RuntimeError(f"command payload created injection marker: {command!r}")
    return completed


def inventory_strategies() -> dict[str, str]:
    raw = json.loads(INVENTORY.read_text(encoding="utf-8"))
    strategies: dict[str, str] = {}
    for name, row in raw["executables"].items():
        strategy = row.get("fuzzStrategy")
        if isinstance(strategy, str) and strategy:
            strategies[name] = strategy
    return strategies


def main() -> int:
    MARKER.unlink(missing_ok=True)
    strategies = inventory_strategies()
    commands = set(strategies)
    if not commands:
        raise SystemExit("installed fuzz inventory contains no strategies")

    for name in sorted(commands):
        if not pathlib.Path(f"/run/current-system/sw/bin/{name}").exists() and not shutil_which(name):
            raise RuntimeError(f"installed custom command is missing: {name}")

    for name, strategy in sorted(strategies.items()):
        if strategy == "unknown-argv":
            for payload in PAYLOADS:
                run([name, "--fuzz-" + payload])
        elif strategy == "unknown-verb":
            for payload in PAYLOADS:
                run([name, "fuzz-" + payload])
        elif strategy == "feature-id":
            for payload in PAYLOADS:
                run([name, "set", payload, "always"])
        elif strategy == "username":
            for payload in PAYLOADS:
                run([name, "account", "apply", "--username", payload, "--disabled"])
        elif strategy == "output-path":
            for payload in PAYLOADS:
                # Relative hostile paths must be rejected before any secret is read or file is written.
                run([name, payload])
        elif strategy == "alert-header":
            run([name, "bad\r\nX-NAS-Fuzz: injected", "must not send"], allowed={2})
            run([name, "x" * 201, "must not send"], allowed={2})
        elif strategy == "disabled-state":
            run([name])
        elif strategy in {"protocol-system-test", "system-lifecycle", "disposable-zfs-lifecycle"}:
            # Covered by guest-test.sh / encrypted-guest-test.sh with real service/storage state.
            continue
        else:
            raise RuntimeError(f"unknown fuzz strategy for {name}: {strategy}")

    print(json.dumps({"ok": True, "commands": len(commands), "strategies": strategies}, sort_keys=True))
    return 0


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


if __name__ == "__main__":
    raise SystemExit(main())
