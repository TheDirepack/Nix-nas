#!/usr/bin/env python3
"""Compile Python sources in memory without creating bytecode caches."""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATHS = (ROOT / "services", ROOT / "scripts", ROOT / "tests")


def main() -> int:
    failures: list[str] = []
    count = 0
    for directory in PATHS:
        for path in sorted(directory.rglob("*.py")):
            count += 1
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except (OSError, SyntaxError) as exc:
                failures.append(f"{path.relative_to(ROOT)}: {exc}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"python syntax ok: {count} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
