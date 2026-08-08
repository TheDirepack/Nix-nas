#!/usr/bin/env python3
"""Ensure every NAS-owned runtime executable remains attached to unit and system tests."""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "tests" / "custom-script-contracts.json"

# Developer-only convenience wrappers are not shipped runtime surfaces. Their
# underlying executable paths are already covered by the inventory separately.
NON_RUNTIME_REPOSITORY_EXECUTABLES = {
    "scripts/vm-pytest.sh",
}

INSTALLED_FUZZ_STRATEGIES = {
    "alert-header",
    "disabled-state",
    "disposable-zfs-lifecycle",
    "feature-id",
    "output-path",
    "protocol-system-test",
    "system-lifecycle",
    "unknown-argv",
    "unknown-verb",
    "username",
}
SOURCE_FUZZ_STRATEGIES = {
    "aggregate-contract",
    "hostile-argv",
    "shell-parse",
    "source-check",
    "syntax-contract",
    "unknown-option",
}


def fail(message: str) -> None:
    print(f"test inventory error: {message}", file=sys.stderr)
    raise SystemExit(1)


def pyproject_commands() -> dict[str, set[str]]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = text.split("[project.scripts]", 1)[1].split("\n[", 1)[0]
    commands: dict[str, set[str]] = {}
    for line in block.splitlines():
        match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*"([A-Za-z0-9_]+):main"$', line.strip())
        if match:
            commands.setdefault(match.group(1), set()).add(f"services/{match.group(2)}.py")
    return commands


def nix_commands() -> dict[str, set[str]]:
    commands: dict[str, set[str]] = {}
    pattern = re.compile(r"name\s*=\s*\"([^\"]+)\"\s*;")
    for path in sorted((ROOT / "modules").rglob("*.nix")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"pkgs\.writeShellApplication\s*\{(.*?)\n\s*\};", text, re.DOTALL):
            name = pattern.search(match.group(1))
            if name:
                commands.setdefault(name.group(1), set()).add(path.relative_to(ROOT).as_posix())
    return commands


def repository_executables() -> dict[str, set[str]]:
    commands: dict[str, set[str]] = {}
    roots = (ROOT / "scripts",)
    for root in roots:
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            try:
                first = path.open("rb").readline(256)
            except OSError:
                continue
            if first.startswith(b"#!"):
                relative = path.relative_to(ROOT).as_posix()
                if relative in NON_RUNTIME_REPOSITORY_EXECUTABLES:
                    continue
                commands.setdefault(relative, set()).add(relative)
    build = ROOT / "cockpit" / "build.js"
    if build.read_bytes().startswith(b"#!"):
        relative = build.relative_to(ROOT).as_posix()
        commands.setdefault(relative, set()).add(relative)
    return commands


def main() -> int:
    raw = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if (
        raw.get("schemaVersion") != 3
        or not isinstance(raw.get("executables"), dict)
        or not isinstance(raw.get("pythonModules"), dict)
    ):
        fail("malformed tests/custom-script-contracts.json")
    entries = raw["executables"]
    discovered: dict[str, set[str]] = {}
    for source in (pyproject_commands(), nix_commands(), repository_executables()):
        for name, paths in source.items():
            discovered.setdefault(name, set()).update(paths)
    installed_commands = set(pyproject_commands()) | set(nix_commands())
    source_commands = set(repository_executables())
    missing = sorted(set(discovered) - set(entries))
    stale = sorted(set(entries) - set(discovered))
    if missing:
        fail("runtime executable(s) lack test contracts: " + ", ".join(missing))
    if stale:
        fail("test inventory names no longer exist: " + ", ".join(stale))
    service_modules = {path.relative_to(ROOT).as_posix() for path in (ROOT / "services").glob("*.py")}
    declared_modules = set(raw["pythonModules"])
    missing_modules = sorted(service_modules - declared_modules)
    stale_modules = sorted(declared_modules - service_modules)
    if missing_modules:
        fail("service module(s) lack focused test contracts: " + ", ".join(missing_modules))
    if stale_modules:
        fail("test inventory names missing service module(s): " + ", ".join(stale_modules))
    for module, tests in sorted(raw["pythonModules"].items()):
        if not isinstance(tests, list) or not tests:
            fail(f"{module}: no focused module tests declared")
        for test in tests:
            if not isinstance(test, str) or not (ROOT / test).is_file():
                fail(f"{module}: missing declared module test {test!r}")

    for name, sources in sorted(discovered.items()):
        row = entries[name]
        declared_sources = row.get("sources")
        if declared_sources is None:
            declared_sources = [row.get("source")]
        if not isinstance(declared_sources, list) or set(declared_sources) != sources:
            fail(f"{name}: sources are {declared_sources!r}; expected {sorted(sources)!r}")
        tests = row.get("tests")
        system_test = row.get("systemTest")
        fuzz_strategy = row.get("fuzzStrategy")
        if not isinstance(tests, list) or not tests:
            fail(f"{name}: no focused tests declared")
        for test in [*tests, system_test]:
            if not isinstance(test, str) or not (ROOT / test).is_file():
                fail(f"{name}: missing declared test {test!r}")
        if name in installed_commands:
            if not isinstance(fuzz_strategy, str) or not fuzz_strategy:
                fail(f"{name}: installed executable has no fuzzStrategy")
            if fuzz_strategy not in INSTALLED_FUZZ_STRATEGIES:
                fail(f"{name}: unsupported fuzzStrategy {fuzz_strategy!r}")
            system_text = (ROOT / system_test).read_text(encoding="utf-8")
            if name not in system_text and system_test != "tests/vm/adversarial-installed.py":
                fail(f"{name}: declared installed-system test does not reference the executable")
        elif fuzz_strategy is not None and not isinstance(fuzz_strategy, str):
            fail(f"{name}: fuzzStrategy must be a string when present")
        source_strategy = row.get("sourceFuzzStrategy")
        if name in source_commands:
            if not isinstance(source_strategy, str) or not source_strategy:
                fail(f"{name}: repository executable has no sourceFuzzStrategy")
            if source_strategy not in SOURCE_FUZZ_STRATEGIES:
                fail(f"{name}: unsupported sourceFuzzStrategy {source_strategy!r}")
        elif source_strategy is not None:
            fail(f"{name}: sourceFuzzStrategy is only valid for repository executables")
    print(f"custom test inventory ok: {len(discovered)} executables, {len(service_modules)} service modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
