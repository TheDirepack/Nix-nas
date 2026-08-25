#!/usr/bin/env python3
"""Reject application-specific knowledge in generic Managed Services V2 code."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

APPLICATION_NAMES = (
    "copyparty",
    "syncthing",
    "vaultwarden",
    "open-webui",
    "llama-swap",
    "deepseek-harness",
    "grafana",
    "victoriametrics",
    "telegraf",
    "vmalert",
    "ntfy",
    "hfdownloader",
    "nut-webgui",
    "coding-agent",
)

GENERIC_PATHS = (
    *sorted((ROOT / "services").glob("nas_v2_*.py")),
    ROOT / "modules/nas/config/managed-services.nix",
    ROOT / "modules/nas/config/managed-services-lifecycle.nix",
    ROOT / "modules/nas/config/managed-services-transactions.nix",
    ROOT / "modules/nas/config/managed-services-network-platform.nix",
    ROOT / "modules/nas/config/managed-services-authentik-blueprint.nix",
    ROOT / "modules/nas/config/managed-services-compose-import.nix",
)


def violations(paths: tuple[pathlib.Path, ...] = GENERIC_PATHS) -> list[tuple[pathlib.Path, str, int]]:
    patterns = {
        name: re.compile(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", re.IGNORECASE) for name in APPLICATION_NAMES
    }
    result: list[tuple[pathlib.Path, str, int]] = []
    for path in paths:
        if not path.is_file():
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for name, pattern in patterns.items():
                if pattern.search(line):
                    result.append((path.relative_to(ROOT), name, line_number))
    return result


def main() -> int:
    found = violations()
    if found:
        for path, name, line_number in found:
            print(f"architecture boundary violation: {path}:{line_number}: {name}", file=sys.stderr)
        return 1
    print(f"architecture boundary ok: {len(GENERIC_PATHS)} generic paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
