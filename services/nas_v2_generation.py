#!/usr/bin/env python3
"""Immutable publication boundary for Managed Services V2 runtime projections.

A reconciliation is compiled and validated in a private staging directory.  A
successful staging tree is sealed read-only and published as a generation
keyed by the desired-state Git revision plus a deterministic projection hash.
Consumers continue to use the historical /run/nas-control paths through stable
symlinks; switching the single ``current`` link selects the complete generation.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import tempfile
from collections.abc import Mapping
from typing import Any


class GenerationError(RuntimeError):
    """Raised when a generated runtime tree cannot be published safely."""


_REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def create_staging(root: pathlib.Path) -> pathlib.Path:
    """Create one private staging directory beneath ``root``."""
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    try:
        metadata = root.lstat()
    except OSError as exc:  # pragma: no cover - defensive OS boundary
        raise GenerationError(f"unable to inspect generation root {root}: {exc}") from exc
    if not metadata or not root.is_dir() or root.is_symlink():
        raise GenerationError(f"generation root must be a real directory: {root}")
    return pathlib.Path(tempfile.mkdtemp(prefix=".staging-", dir=root))


def _tree_digest(root: pathlib.Path) -> str:
    """Hash the validated projection independently of its staging pathname."""
    digest = hashlib.sha256()
    try:
        entries = sorted((path for path in root.rglob("*") if path.is_file()), key=lambda path: str(path.relative_to(root)))
    except OSError as exc:
        raise GenerationError(f"unable to enumerate staged generation {root}: {exc}") from exc
    for path in entries:
        relative = path.relative_to(root).as_posix()
        # plan.changedFiles contains absolute staging paths and is diagnostic,
        # not executable projection state.  Everything else participates in the
        # generation identity, including source-derived systemd fingerprints.
        if relative == "plan.json":
            continue
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise GenerationError(f"unable to read staged generation file {path}: {exc}") from exc
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _seal_tree(root: pathlib.Path) -> None:
    """Make generated files immutable to ordinary runtime writers."""
    files = sorted((path for path in root.rglob("*") if path.is_file()), key=lambda path: len(path.parts), reverse=True)
    directories = sorted((path for path in root.rglob("*") if path.is_dir()), key=lambda path: len(path.parts), reverse=True)
    for path in files:
        os.chmod(path, 0o444)
    for path in directories:
        os.chmod(path, 0o555)
    os.chmod(root, 0o555)


def _fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_symlink(path: pathlib.Path, target: str) -> None:
    """Atomically install a symlink, migrating an old generated directory once."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.link-{os.getpid()}"
    temporary.unlink(missing_ok=True)
    os.symlink(target, temporary)
    try:
        if path.exists() and path.is_dir() and not path.is_symlink():
            legacy = path.parent / f".{path.name}.legacy-{os.getpid()}"
            legacy.unlink(missing_ok=True)
            os.replace(path, legacy)
            os.replace(temporary, path)
            shutil.rmtree(legacy, ignore_errors=True)
        else:
            os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def publish_generation(
    staging: pathlib.Path,
    *,
    plan: Mapping[str, Any],
    generation_root: pathlib.Path,
    current_link: pathlib.Path,
    compatibility_paths: Mapping[pathlib.Path, pathlib.PurePosixPath],
) -> pathlib.Path:
    """Seal and atomically select one validated generation.

    ``compatibility_paths`` maps historical absolute consumer paths to their
    relative location inside the generation.  Those links are stable and point
    through ``current``; only the current link changes between reconciliations.
    """
    revision = plan.get("desiredRevision")
    if not isinstance(revision, str) or _REVISION_RE.fullmatch(revision) is None:
        raise GenerationError("immutable generation publication requires the desired-state Git revision")
    try:
        staging.relative_to(generation_root)
    except ValueError as exc:
        raise GenerationError("staging directory is outside the generation root") from exc

    projection_hash = _tree_digest(staging)
    destination = generation_root / f"{revision}-{projection_hash[:16]}"
    if destination.exists():
        if not destination.is_dir() or destination.is_symlink():
            raise GenerationError(f"generation destination is not a real directory: {destination}")
        shutil.rmtree(staging)
    else:
        _seal_tree(staging)
        try:
            os.replace(staging, destination)
        except OSError as exc:
            raise GenerationError(f"unable to publish generation {destination}: {exc}") from exc
        _fsync_directory(generation_root)

    # Install compatibility links before selecting the generation.  On the
    # first upgrade these can temporarily point through an absent `current`,
    # but no consumer is activated until the compiler exits successfully.
    current_name = current_link.name
    for stable, relative in compatibility_paths.items():
        if stable == current_link:
            continue
        if stable.parent != current_link.parent:
            raise GenerationError(f"compatibility path must share the current-link parent: {stable}")
        _replace_symlink(stable, f"{current_name}/{relative.as_posix()}")

    relative_destination = os.path.relpath(destination, current_link.parent)
    _replace_symlink(current_link, relative_destination)
    return destination


def discard_staging(path: pathlib.Path) -> None:
    """Best-effort cleanup for a failed compile/validation."""
    try:
        if path.exists() and path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
    except OSError:
        pass


__all__ = [
    "GenerationError",
    "create_staging",
    "discard_staging",
    "publish_generation",
]
