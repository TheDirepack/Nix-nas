#!/usr/bin/env python3
"""Require every remaining lib.mkForce use to match the reviewed allowlist."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERN = re.compile(r"^\s*([A-Za-z0-9_.]+)\s*=\s*lib\.mkForce\b")


def main() -> int:
    expected_data = json.loads((ROOT / "policy/mkforce-allowlist.json").read_text(encoding="utf-8"))
    expected = Counter(
        (entry["path"], entry["setting"]) for entry in expected_data["entries"] for _ in range(entry["count"])
    )
    actual: Counter[tuple[str, str]] = Counter()
    for path in (ROOT / "modules").rglob("*.nix"):
        relative = path.relative_to(ROOT).as_posix()
        for line in path.read_text(encoding="utf-8").splitlines():
            match = PATTERN.search(line)
            if match:
                actual[(relative, match.group(1))] += 1
    if actual != expected:
        print("lib.mkForce allowlist mismatch")
        print(f"expected: {dict(expected)}")
        print(f"actual: {dict(actual)}")
        return 1
    for entry in expected_data["entries"]:
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            print(f"missing rationale: {entry}")
            return 1
    print(f"Validated {sum(actual.values())} reviewed lib.mkForce use(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
