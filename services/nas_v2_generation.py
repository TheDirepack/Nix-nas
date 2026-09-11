#!/usr/bin/env python3
"""Immutable publication boundary for Managed Services V2 runtime projections.

Each reconciliation is compiled and validated inside its final, unpublished
revision-keyed directory.  Only after every projection validates is the tree
sealed read-only and the single ``current`` symlink atomically switched.
Historical /run/nas-control paths remain compatibility symlinks through
``current`` so consumers do not need their own revision database.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
from collections.abc import Mapping
from typing import Any


class GenerationError(RuntimeError):
    """Raised when a generated runtime tree cannot be published safely."""


_REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GENERATION_SUFFIX_MIN = 2
_GENERATION_SUFFIX_MAX = 9999
_GENERATION_NAME_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?(?:-(?:[2-9]|[1-9][0-9]{1,3}))?$")


def validate_revision(revision: str) -> str:
    if not isinstance(revision, str) or _REVISION_RE.fullmatch(revision) is None:
        raise GenerationError(f"invalid desired-state Git revision {revision!r}")
    return revision


def format_generation_name(revision: str, index: int) -> str:
    """Render the single allocator-owned directory name for a revision slot."""
    revision = validate_revision(revision)
    if (
        not isinstance(index, int)
        or isinstance(index, bool)
        or (index != 1 and not _GENERATION_SUFFIX_MIN <= index <= _GENERATION_SUFFIX_MAX)
    ):
        raise GenerationError(f"invalid generation index {index!r}")
    return revision if index == 1 else f"{revision}-{index}"


def parse_generation_name(name: str) -> tuple[str, int] | None:
    """Split a generation directory name into its revision and slot index."""
    if not isinstance(name, str) or _GENERATION_NAME_RE.fullmatch(name) is None:
        return None
    revision, separator, suffix = name.rpartition("-")
    if not separator:
        return name, 1
    return revision, int(suffix)


def allocate_generation(root: pathlib.Path, revision: str) -> pathlib.Path:
    """Reserve a unique final pathname whose prefix is the desired Git SHA.

    Reusing the same desired revision is legitimate on boot or when a watched
    runtime source changes.  A numeric suffix preserves prior immutable output
    while keeping every generation visibly keyed by the authority revision.
    """
    revision = validate_revision(revision)
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    if root.is_symlink() or not root.is_dir():
        raise GenerationError(f"generation root must be a real directory: {root}")
    for index in range(1, _GENERATION_SUFFIX_MAX + 1):
        name = format_generation_name(revision, index)
        candidate = root / name
        try:
            candidate.mkdir(mode=0o700)
            return candidate
        except FileExistsError:
            if candidate.is_symlink() or not candidate.is_dir():
                raise GenerationError(f"generation path is not a real directory: {candidate}")
            continue
        except OSError as exc:
            raise GenerationError(f"unable to allocate generation {candidate}: {exc}") from exc
    raise GenerationError(f"too many generations exist for desired revision {revision}")


def _seal_tree(root: pathlib.Path) -> None:
    """Make generated files immutable to ordinary runtime writers."""
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        os.chmod(path, 0o444)
    for path in sorted(
        (item for item in root.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        os.chmod(path, 0o555)
    os.chmod(root, 0o555)


def _fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_symlink(path: pathlib.Path, target: str) -> None:
    """Atomically install a symlink, migrating one old generated directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.link-{os.getpid()}"
    temporary.unlink(missing_ok=True)
    os.symlink(target, temporary)
    legacy: pathlib.Path | None = None
    try:
        if path.exists() and path.is_dir() and not path.is_symlink():
            legacy = path.parent / f".{path.name}.legacy-{os.getpid()}"
            if legacy.exists() or legacy.is_symlink():
                raise GenerationError(f"refusing to overwrite legacy migration path {legacy}")
            os.replace(path, legacy)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        if legacy is not None and legacy.exists() and not path.exists():
            os.replace(legacy, path)
        raise
    finally:
        temporary.unlink(missing_ok=True)
    if legacy is not None:
        shutil.rmtree(legacy, ignore_errors=True)


def _validate_compatibility_paths(
    compatibility_paths: Mapping[pathlib.Path, pathlib.PurePosixPath],
    *,
    current_link: pathlib.Path,
) -> None:
    """Validate the complete stable-link set before mutating the candidate."""
    for stable, relative in compatibility_paths.items():
        if stable.parent != current_link.parent:
            raise GenerationError(f"compatibility path must share the current-link parent: {stable}")
        if stable == current_link:
            raise GenerationError("compatibility path must not replace the current-generation link")
        if not isinstance(relative, pathlib.PurePosixPath) or relative.is_absolute() or not relative.parts:
            raise GenerationError(f"invalid compatibility target for {stable}: {relative}")
        if any(part in {".", ".."} for part in relative.parts):
            raise GenerationError(f"invalid compatibility target for {stable}: {relative}")


def publish_generation(
    generation: pathlib.Path,
    *,
    expected_revision: str,
    plan: Mapping[str, Any],
    generation_root: pathlib.Path,
    current_link: pathlib.Path,
    compatibility_paths: Mapping[pathlib.Path, pathlib.PurePosixPath],
) -> pathlib.Path:
    """Seal and atomically select one completely validated generation."""
    expected_revision = validate_revision(expected_revision)
    actual_revision = plan.get("desiredRevision")
    if actual_revision != expected_revision:
        raise GenerationError(
            "desired state changed while the generation was compiling; refusing to publish a mixed revision"
        )
    try:
        generation.relative_to(generation_root)
    except ValueError as exc:
        raise GenerationError("generation directory is outside the generation root") from exc
    if generation.is_symlink() or not generation.is_dir():
        raise GenerationError(f"generation must be a real directory: {generation}")
    parsed = parse_generation_name(generation.name)
    if parsed is None or parsed[0] != expected_revision:
        raise GenerationError("generation directory is not keyed by the expected desired-state revision")

    _validate_compatibility_paths(compatibility_paths, current_link=current_link)
    _seal_tree(generation)
    _fsync_directory(generation_root)

    # These links are stable after the first migration and always traverse the
    # one current-generation pointer.  The current link is switched last.
    current_name = current_link.name
    for stable, relative in compatibility_paths.items():
        _replace_symlink(stable, f"{current_name}/{relative.as_posix()}")

    relative_generation = os.path.relpath(generation, current_link.parent)
    _replace_symlink(current_link, relative_generation)
    return generation


def prune_generations(
    generation_root: pathlib.Path,
    *,
    current_link: pathlib.Path,
    retain: int = 3,
) -> list[pathlib.Path]:
    """Remove old immutable generations without ever deleting the active one."""
    if retain < 1:
        raise GenerationError("generation retention must be at least one")
    if not generation_root.exists():
        return []
    try:
        current = current_link.resolve(strict=True)
        current.relative_to(generation_root.resolve())
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise GenerationError("current generation link does not resolve beneath the generation root") from exc

    candidates = [
        path
        for path in generation_root.iterdir()
        if path.is_dir() and not path.is_symlink() and _GENERATION_NAME_RE.fullmatch(path.name)
    ]
    candidates.sort(key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True)
    keep = {current}
    for path in candidates:
        if len(keep) >= retain:
            break
        keep.add(path)

    removed: list[pathlib.Path] = []
    for path in candidates:
        if path in keep:
            continue
        try:
            shutil.rmtree(path)
        except OSError as exc:
            raise GenerationError(f"unable to prune old generation {path}: {exc}") from exc
        removed.append(path)
    return removed


def _refuse_if_current(path: pathlib.Path, current_link: pathlib.Path) -> None:
    if not current_link.exists() and not current_link.is_symlink():
        return
    try:
        current = current_link.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise GenerationError("refusing generation cleanup because current cannot be resolved safely") from exc
    if current == path:
        raise GenerationError(f"refusing to discard current generation {path}")


def discard_generation(path: pathlib.Path, *, current_link: pathlib.Path) -> None:
    """Best-effort cleanup of one candidate not selected by ``current``.

    Sealing is a filesystem-integrity step, not publication bookkeeping. A
    failed publication may therefore leave a sealed candidate that still must
    be removed. The current symlink is the sole publication authority.
    """
    try:
        if path.exists() and path.is_dir() and not path.is_symlink():
            resolved = path.resolve(strict=True)
            _refuse_if_current(resolved, current_link)
            os.chmod(path, 0o700)
            for directory in (item for item in path.rglob("*") if item.is_dir()):
                try:
                    os.chmod(directory, 0o700)
                except OSError:
                    pass
            _refuse_if_current(resolved, current_link)
            shutil.rmtree(path)
    except GenerationError:
        raise
    except OSError:
        pass


__all__ = [
    "GenerationError",
    "allocate_generation",
    "discard_generation",
    "format_generation_name",
    "parse_generation_name",
    "publish_generation",
    "prune_generations",
    "validate_revision",
]
