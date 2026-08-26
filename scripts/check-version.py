#!/usr/bin/env python3
"""Verify that user-visible release metadata matches VERSION."""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def fail(message: str) -> None:
    print(f"version error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    expected_heading = f"# NixOS NAS {VERSION}"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_heading = readme.splitlines()[0]
    if readme_heading != expected_heading:
        fail(f"README heading is {readme_heading!r}; expected {expected_heading!r}")
    if f"> **Release status:** {VERSION}" not in readme:
        fail("README release status does not match VERSION")

    package = json.loads((ROOT / "cockpit" / "package.json").read_text(encoding="utf-8"))
    if package.get("version") != VERSION:
        fail(f"cockpit/package.json version is {package.get('version')!r}; expected {VERSION!r}")

    lock = json.loads((ROOT / "cockpit" / "package-lock.json").read_text(encoding="utf-8"))
    root_package = lock.get("packages", {}).get("")
    if lock.get("version") != VERSION:
        fail("cockpit/package-lock.json version does not match VERSION")
    if not isinstance(root_package, dict) or root_package.get("version") != VERSION:
        fail("cockpit/package-lock.json root package version does not match VERSION")

    flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
    description = re.search(r'^\s*description\s*=\s*"([^"]+)";', flake, re.MULTILINE)
    if description is None or VERSION not in description.group(1):
        fail("flake description does not contain VERSION")

    changelog_headings = [
        line for line in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines() if line.startswith("## ")
    ]
    if not changelog_headings or not changelog_headings[0].startswith(f"## {VERSION} "):
        fail("first changelog release does not match VERSION")

    print(f"version metadata ok: {VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
