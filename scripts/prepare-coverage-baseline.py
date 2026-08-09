#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


FIXES = (
    (
        "tests/test_alpha20_cockpit.py",
        '        self.assertIn("qemu-evidence", workflow)\n',
        "",
    ),
    (
        "tests/test_alpha20_cockpit.py",
        '        self.assertIn("installer-evidence", workflow)\n',
        "",
    ),
    (
        "tests/test_managed_service.py",
        '"exposure": {"type": "dns", "value": "app.nas.local"}',
        '"exposure": {"type": "dns", "value": "app.service.local"}',
    ),
    (
        "tests/test_service_caddy_validate.py",
        '"exposure": {"type": "path", "value": "/api"}',
        '"exposure": {"type": "path", "value": "/managed-api"}',
    ),
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
    if stale_fixes and len(stale_fixes) != len(FIXES):
        raise ValueError(f"baseline is partially corrected: found {len(stale_fixes)} of {len(FIXES)} stale fixtures")
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
