from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CODE_ROOTS = [
    ROOT / "authentik",
    ROOT / "cockpit",
    ROOT / "installation",
    ROOT / "modules",
    ROOT / "scripts",
    ROOT / "services",
    ROOT / "tests",
    ROOT / "web",
]
ROOT_FILES = [
    ROOT / "flake.nix",
    ROOT / "hardware-configuration.nix",
    ROOT / "hfdownloader-image.nix",
    ROOT / "local.nix",
    ROOT / "ruff.toml",
]
SUFFIXES = {".py", ".nix", ".sh", ".js", ".jsx", ".mjs", ".css", ".scss", ".yaml", ".yml", ".toml"}
DIRECTIVE_PREFIXES = (
    "#!",
    "# noqa",
    "# renovate:",
    "# yaml-language-server:",
)
BANNED_COMMENT_TEXT = re.compile(
    r"\b(?:TODO|FIXME|HACK)\b|alpha\.\d+|former monolithic|review finding|"
    r"decision tree|weird anomal|historical|previously",
    re.IGNORECASE,
)


def source_files() -> list[Path]:
    files = [path for path in ROOT_FILES if path.exists()]
    for directory in CODE_ROOTS:
        files.extend(
            path
            for path in directory.rglob("*")
            if path.is_file()
            and path.suffix in SUFFIXES
            and "node_modules" not in path.parts
            and "dist" not in path.parts
            and ".git" not in path.parts
        )
    return sorted(set(files))


def comment_text(path: Path, line: str) -> str | None:
    stripped = line.lstrip()
    if path.suffix in {".py", ".nix", ".sh", ".yaml", ".yml", ".toml"}:
        if not stripped.startswith("#") or stripped.startswith(DIRECTIVE_PREFIXES):
            return None
        return stripped[1:].strip()
    if path.suffix in {".js", ".jsx", ".mjs", ".css", ".scss"} and stripped.startswith("//"):
        return stripped[2:].strip()
    return None


class CommentPolicyTests(unittest.TestCase):
    def test_comments_do_not_store_history_or_backlog(self) -> None:
        failures: list[str] = []
        for path in source_files():
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                text = comment_text(path, line)
                if text is not None and BANNED_COMMENT_TEXT.search(text):
                    failures.append(f"{path.relative_to(ROOT)}:{line_number}: {text}")
        self.assertEqual([], failures)


if __name__ == "__main__":
    unittest.main()
