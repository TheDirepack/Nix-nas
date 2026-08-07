#!/usr/bin/env python3
"""Check relative links in hand-written root and repository documentation."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SOURCES = [
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    *sorted((ROOT / "docs/development").glob("*.md")),
    *sorted((ROOT / "docs/operator").glob("*.md")),
]


def main() -> int:
    errors: list[str] = []
    checked = 0
    for source in SOURCES:
        content = source.read_text(encoding="utf-8")
        for raw_target in LINK_RE.findall(content):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            relative = target.split("#", maxsplit=1)[0].split("?", maxsplit=1)[0]
            if not relative:
                continue
            checked += 1
            destination = (source.parent / relative).resolve()
            try:
                destination.relative_to(ROOT)
            except ValueError:
                errors.append(f"{source.relative_to(ROOT)}: link escapes repository: {target}")
                continue
            if not destination.exists():
                errors.append(f"{source.relative_to(ROOT)}: missing target: {target}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"documentation links ok: {checked} relative links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
