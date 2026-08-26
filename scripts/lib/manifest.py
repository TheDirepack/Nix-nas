#!/usr/bin/env python3
"""Deterministic MANIFEST.sha256 generator for release artefacts and tests."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import stat


known_generated = {".coverage", "coverage.json"}
ignored_parts = {
    ".cache",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    ".direnv",
    ".venv",
    ".hypothesis",
    ".ruff_cache",
    ".mypy_cache",
}
ignored_suffixes = {".pyc", ".zip", ".qcow2", ".iso", ".log"}
ignored_release_suffixes = (".zip.sha256", ".provenance.json")


def _is_ignored(relative: pathlib.PurePath) -> bool:
    if any(part in ignored_parts or part.endswith(".egg-info") for part in relative.parts):
        return True
    if relative.name in known_generated or relative.suffix in ignored_suffixes:
        return True
    return relative.name.endswith(ignored_release_suffixes)


def generate_manifest(root: pathlib.Path, output: pathlib.Path) -> pathlib.Path:
    root = root.resolve()
    if not root.is_dir():
        raise SystemExit(f"manifest root is not a directory: {root}")
    rows: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if relative.as_posix() in {"MANIFEST.sha256", ".release-input-policy"}:
            continue
        if _is_ignored(relative):
            continue
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise SystemExit(f"unable to stat {relative}: {exc}") from exc
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise SystemExit(f"staged release contains unsupported object: {relative}")
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise SystemExit(f"unable to read {relative}: {exc}") from exc
        rows.append(f"{digest}  ./{relative.as_posix()}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")
    try:
        fd = os.open(output, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
    try:
        fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
    return output


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="root directory to hash")
    parser.add_argument("--out", required=True, help="output MANIFEST.sha256 path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    generate_manifest(pathlib.Path(args.root), pathlib.Path(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
