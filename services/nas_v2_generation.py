#!/usr/bin/env python3
"""Immutable publication boundary for Managed Services V2 runtime projections.

Each reconciliation is compiled and validated inside its final, unpublished
revision-keyed directory. Only after every projection validates is the tree
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

from nas_common import fsync_directory as _fsync_directory


class GenerationError(RuntimeError):
    """Raised when a generated runtime tree cannot be published safely."""


_REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GENERATION_SUFFIX_MIN = 2
_GENERATION_SUFFIX_MAX = 9999
_GENERATION_NAME_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?(?:-(?:[2-9]|[1-9][0-9]{1,3}))?$")

# Caddy validates and imports the published ``caddy-managed.conf`` after the
# generation is sealed, so the sealed tree must be group-readable by the Caddy
# system group.  Use the existing account/group rather than introducing a
# second group registry that could drift from the service definition.
CADDY_READER_GROUP = "caddy"


def _reader_gid(reader_group: str | int | None) -> int | None:
    if reader_group is None:
        return None
    import grp

    try:
        if isinstance(reader_group, int) and not isinstance(reader_group, bool):
            return grp.getgrgid(reader_group).gr_gid
        if isinstance(reader_group, str) and reader_group:
            if reader_group.isdigit():
                return grp.getgrgid(int(reader_group)).gr_gid
            return grp.getgrnam(reader_group).gr_gid
    except KeyError as exc:
        raise GenerationError(f"sealed generation reader group {reader_group!r} does not exist") from exc
    raise GenerationError(f"invalid sealed generation reader group {reader_group!r}")


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
    runtime source changes. A numeric suffix preserves prior immutable output
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


def _set_group(path: pathlib.Path, gid: int | None) -> None:
    if gid is None:
        return
    try:
        os.chown(path, -1, gid)
    except OSError as exc:
        raise GenerationError(f"unable to grant sealed generation group access to {path}: {exc}") from exc


def _seal_tree(root: pathlib.Path, *, reader_group: str | int | None = None) -> None:
    """Make generated files immutable to ordinary runtime writers.

    With no reader group the tree is owner-only. When ``reader_group`` names a
    group that a consumer service runs under (Caddy reads the managed Caddyfile
    after publication), the tree becomes group-readable but never group- or
    world-writable and never world-readable:
    directories ``0o550`` and files ``0o440``.
    """
    gid = _reader_gid(reader_group)
    directory_mode = 0o550 if gid is not None else 0o500
    file_mode = 0o440 if gid is not None else 0o400
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        os.chmod(path, file_mode)
        _set_group(path, gid)
    for path in sorted(
        (item for item in root.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        os.chmod(path, directory_mode)
        _set_group(path, gid)
    os.chmod(root, directory_mode)
    _set_group(root, gid)


def _grant_reader_traversal(generation_root: pathlib.Path, *, reader_group: str | int | None) -> None:
    """Allow the consumer group to traverse into revision directories.

    ``allocate_generation`` inherits the reconciler umask, which can leave the
    parent ``generations`` directory unreadable to Caddy even after the
    generation itself is sealed group-readable.
    """
    gid = _reader_gid(reader_group)
    if gid is None:
        return
    if generation_root.is_symlink() or not generation_root.is_dir():
        raise GenerationError(f"generation root must be a real directory: {generation_root}")
    try:
        os.chmod(generation_root, 0o750)
    except OSError as exc:
        raise GenerationError(f"unable to grant sealed generation group access to {generation_root}: {exc}") from exc
    _set_group(generation_root, gid)


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
    reader_group: str | int | None = None,
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
    _seal_tree(generation, reader_group=reader_group)
    _grant_reader_traversal(generation_root, reader_group=reader_group)
    _fsync_directory(generation_root)

    # These links are stable after the first migration and always traverse the
    # one current-generation pointer. The current link is switched last.
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
        keep.add(path.resolve())

    removed: list[pathlib.Path] = []
    for path in candidates:
        if path.resolve() in keep:
            continue
        try:
            _unseal_tree(path)
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


def _unseal_tree(path: pathlib.Path) -> None:
    """Make a sealed generation tree writable again so shutil.rmtree can remove it.

    Both directories and files are restored to owner-writable modes; sealed
    files are read-only (0o400) and would otherwise block removal.
    """
    os.chmod(path, 0o700)
    for item in path.rglob("*"):
        try:
            if item.is_dir():
                os.chmod(item, 0o700)
            else:
                os.chmod(item, 0o600)
        except OSError:
            pass


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
            _unseal_tree(path)
            _refuse_if_current(resolved, current_link)
            shutil.rmtree(path)
    except GenerationError:
        raise
    except OSError:
        pass


__all__ = [
    "CADDY_READER_GROUP",
    "GenerationError",
    "allocate_generation",
    "discard_generation",
    "format_generation_name",
    "parse_generation_name",
    "publish_generation",
    "prune_generations",
    "validate_revision",
]
