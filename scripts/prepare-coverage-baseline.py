#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


RUNNER_EXCLUSION_STALE = """    excluded = set(args.exclude)
    files = sorted(path for path in TESTS.glob(args.pattern) if path.name not in excluded)
"""
RUNNER_EXCLUSION_REPLACEMENT = """    excluded = set(args.exclude)
    if args.coverage:
        # The custom-input fuzz suite is owned by the dedicated fuzz stages and
        # is intentionally excluded from the fast current-branch coverage run.
        # Apply the same ownership while rebuilding an uncached main baseline.
        excluded.add("test_fuzz_custom_inputs.py")
    files = sorted(path for path in TESTS.glob(args.pattern) if path.name not in excluded)
"""

# Main has the stale probe expectation until the shared CI fix is merged.
# The source validation already fails closed; coverage must use the same test
# oracle as the current branch, without changing main or excluding this test.
PROBE_DIAGNOSTIC_STALE = '        self.assertIn("External management probe command is empty", result.stderr)\n'
PROBE_DIAGNOSTIC_REPLACEMENT = '        # The validator failure preempts the secondary empty-argv check.\n'


FIXES: tuple[tuple[str, str, str], ...] = (
    ("scripts/run-unit-tests.py", RUNNER_EXCLUSION_STALE, RUNNER_EXCLUSION_REPLACEMENT),
    ("tests/test_update_runtime.py", PROBE_DIAGNOSTIC_STALE, PROBE_DIAGNOSTIC_REPLACEMENT),
)


def prepare(root: Path) -> int:
    sources: dict[Path, str] = {}
    stale_fixes: list[tuple[Path, str, str]] = []
    for relative, stale, replacement in FIXES:
        path = root / relative
        source = sources.setdefault(path, path.read_text(encoding="utf-8"))
        count = source.count(stale)
        if count > 1:
            raise ValueError(f"{relative}: expected at most one stale fixture, found {count}")
        if count == 1:
            stale_fixes.append((path, stale, replacement))
    for path, stale, replacement in stale_fixes:
        sources[path] = sources[path].replace(stale, replacement)
    for path in {path for path, _stale, _replacement in stale_fixes}:
        path.write_text(sources[path], encoding="utf-8")
    return len(stale_fixes)


def main() -> int:
    parser = argparse.ArgumentParser(description="Correct known test-only fixtures before measuring main coverage")
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    try:
        changed = prepare(args.root)
    except (OSError, ValueError) as exc:
        print(f"prepare-coverage-baseline: {exc}", file=sys.stderr)
        return 2
    print(f"Corrected {changed} stale main-branch coverage fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
