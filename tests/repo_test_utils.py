from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def keepass_sources() -> str:
    """The KeePass secret system: its Nix packaging plus every Go source."""
    parts = [text("modules/nas/internal/secret-tools.nix")]
    for path in sorted((ROOT / "go").rglob("*.go")):
        if not path.name.endswith("_test.go"):
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)
