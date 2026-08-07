from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")
