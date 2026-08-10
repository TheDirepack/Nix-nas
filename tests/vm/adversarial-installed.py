#!/usr/bin/env python3
"""Property-based adversarial checks for NAS commands in a disposable installed VM."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess

from hypothesis import HealthCheck, example, given, settings, strategies as st

ROOT = pathlib.Path("/var/lib/nas-test/repo")
INVENTORY = ROOT / "tests/custom-script-contracts.json"
MARKER = pathlib.Path("/tmp/nas-installed-fuzz-pwned")
INJECTION_SENTINEL = "$(touch /tmp/nas-installed-fuzz-pwned)"
SKIP_STRATEGIES = {"protocol-system-test", "system-lifecycle", "disposable-zfs-lifecycle"}

# Keep generated argv values valid for execve itself. The strategies below add
# target-specific invalid grammar; NUL bytes and surrogate code points would only
# test Python/subprocess argument marshalling instead of the installed command.
ARGV_CHAR = st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00")
ARGV_TEXT = st.text(alphabet=ARGV_CHAR, max_size=128)
IDENTIFIER_SAFE = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-",
    max_size=24,
)
IDENTIFIER_FORBIDDEN = st.sampled_from(["/", "\\", " ", "\t", "\r", "\n", ";", "|", "&", "$", "`"])


def invalid_identifier() -> st.SearchStrategy[str]:
    """Generate a value guaranteed outside the NAS identifier grammar."""

    malformed = st.builds(
        lambda left, forbidden, right: left + forbidden + right,
        IDENTIFIER_SAFE,
        IDENTIFIER_FORBIDDEN,
        IDENTIFIER_SAFE,
    )
    return st.one_of(st.just(""), malformed)


def traversal_path() -> st.SearchStrategy[str]:
    """Generate a relative path guaranteed to contain parent traversal."""

    leaf = st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",),
            blacklist_characters="/\x00\r\n",
        ),
        min_size=1,
        max_size=48,
    )
    return st.builds(
        lambda depth, value: "../" * depth + value,
        st.integers(min_value=1, max_value=8),
        leaf,
    )


def invalid_alert_header() -> st.SearchStrategy[str]:
    """Generate header injection or a value beyond the accepted bound."""

    injected = st.builds(
        lambda prefix, suffix: prefix + "\r\nX-NAS-Fuzz: injected" + suffix,
        st.text(alphabet=ARGV_CHAR, max_size=32),
        st.text(alphabet=ARGV_CHAR, max_size=32),
    )
    oversized = st.text(alphabet=ARGV_CHAR, min_size=201, max_size=512)
    return st.one_of(injected, oversized)


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


def payload_strategy(strategy: str) -> st.SearchStrategy[str]:
    if strategy in {"unknown-argv", "unknown-verb"}:
        return ARGV_TEXT
    if strategy in {"feature-id", "username"}:
        return invalid_identifier()
    if strategy == "output-path":
        return traversal_path()
    if strategy == "alert-header":
        return invalid_alert_header()
    raise ValueError(f"strategy {strategy!r} has no generated payload")


def exercise_payload(name: str, strategy: str, payload: str) -> None:
    if strategy == "unknown-argv":
        run([name, "--fuzz-" + payload])
    elif strategy == "unknown-verb":
        run([name, "fuzz-" + payload])
    elif strategy == "feature-id":
        run([name, "set", payload, "always"])
    elif strategy == "username":
        run([name, "account", "apply", "--username", payload, "--disabled"])
    elif strategy == "output-path":
        # Traversal must be rejected before a secret is read or a file is written.
        run([name, payload])
    elif strategy == "alert-header":
        run([name, payload, "must not send"], allowed={2})
    else:
        raise ValueError(f"unsupported generated strategy {strategy!r}")


def exercise_strategy(name: str, strategy: str, *, smoke: bool) -> None:
    if strategy in SKIP_STRATEGIES:
        # Real service/storage state is covered by guest-test.sh and encrypted-guest-test.sh.
        return
    if strategy == "disabled-state":
        run([name])
        return

    examples = 3 if smoke else 8

    def property_test(payload: str) -> None:
        exercise_payload(name, strategy, payload)

    generated = given(payload_strategy(strategy))(property_test)
    if strategy in {"unknown-argv", "unknown-verb", "feature-id", "username"}:
        generated = example(INJECTION_SENTINEL)(generated)
    generated = settings(
        max_examples=examples,
        deadline=None,
        database=None,
        suppress_health_check=[HealthCheck.too_slow],
    )(generated)
    generated()


def main() -> int:
    MARKER.unlink(missing_ok=True)
    strategies = inventory_strategies()
    commands = set(strategies)
    if not commands:
        raise SystemExit("installed adversarial inventory contains no strategies")

    smoke = os.environ.get("NAS_INSTALLED_FUZZ_SMOKE") == "1"
    for name in sorted(commands):
        if not pathlib.Path(f"/run/current-system/sw/bin/{name}").exists() and shutil.which(name) is None:
            raise RuntimeError(f"installed custom command is missing: {name}")

    for name, strategy in sorted(strategies.items()):
        exercise_strategy(name, strategy, smoke=smoke)

    print(
        json.dumps(
            {
                "ok": True,
                "commands": len(commands),
                "engine": "hypothesis",
                "generatedExamplesPerStrategy": 3 if smoke else 8,
                "smoke": smoke,
                "strategies": strategies,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
