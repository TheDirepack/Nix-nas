#!/usr/bin/env python3
"""Git-backed history for the Managed Services V2 desired-state authority.

Git is the durable history and rollback store for ``services.yaml``.  Runtime
subsystems remain projections of that file; this module deliberately tracks no
generated state and no second desired-state database.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pathlib
import subprocess
import sys
from contextlib import contextmanager
from typing import Any, Iterator, Sequence

DEFAULT_AUTHORITY = pathlib.Path("/var/lib/nas-control/services.yaml")
DEFAULT_REPOSITORY = pathlib.Path("/var/lib/nas-control/config-history.git")
APPLIED_REF = "refs/nas/applied"
DESIRED_REF = "refs/heads/main"


class DesiredStateHistoryError(RuntimeError):
    """Raised when desired-state history cannot be updated safely."""


@contextmanager
def _authority_lock(authority: pathlib.Path) -> Iterator[None]:
    lock_path = authority.with_name(f".{authority.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _run(
    command: Sequence[str],
    *,
    check: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DesiredStateHistoryError(f"unable to execute {command[0]}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise DesiredStateHistoryError(f"command failed ({result.returncode}): {' '.join(command)}: {detail}")
    return result


def _git(
    repository: pathlib.Path,
    authority: pathlib.Path,
    git_bin: str,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            git_bin,
            f"--git-dir={repository}",
            f"--work-tree={authority.parent}",
            *arguments,
        ],
        check=check,
    )


def ensure_repository(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
) -> None:
    """Create the private bare history repository when it does not exist."""
    if repository.exists():
        if not (repository / "HEAD").is_file():
            raise DesiredStateHistoryError(f"history path is not a Git repository: {repository}")
        return
    repository.parent.mkdir(parents=True, exist_ok=True)
    result = _run([git_bin, "init", "--bare", "--initial-branch=main", str(repository)], check=False)
    if result.returncode != 0:
        # Compatibility fallback for older Git versions.  NixOS normally takes
        # the first path, but keeping this costs almost nothing and helps tests.
        _run([git_bin, "init", "--bare", str(repository)])
        _git(repository, authority, git_bin, "symbolic-ref", "HEAD", DESIRED_REF)
    try:
        os.chmod(repository, 0o750)
    except OSError:
        pass


def _rev_parse(
    repository: pathlib.Path,
    authority: pathlib.Path,
    git_bin: str,
    ref: str,
) -> str | None:
    result = _git(repository, authority, git_bin, "rev-parse", "--verify", ref, check=False)
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value if value else None


def record_desired(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
    message: str = "Update Managed Services V2 desired state",
) -> dict[str, Any]:
    """Commit the exact authority file if its contents changed."""
    if authority.parent == authority:
        raise DesiredStateHistoryError("desired-state authority has no parent work tree")
    if not authority.is_file():
        raise DesiredStateHistoryError(f"desired-state authority is missing: {authority}")
    if not message.strip():
        raise DesiredStateHistoryError("history commit message must not be empty")

    with _authority_lock(authority):
        ensure_repository(authority=authority, repository=repository, git_bin=git_bin)
        relative = authority.name
        _git(repository, authority, git_bin, "add", "--force", "--", relative)
        diff = _git(repository, authority, git_bin, "diff", "--cached", "--quiet", "--", relative, check=False)
        if diff.returncode not in {0, 1}:
            detail = (diff.stderr or diff.stdout).strip()[:4000]
            raise DesiredStateHistoryError(f"unable to compare desired-state history: {detail}")
        changed = diff.returncode == 1
        if changed:
            _git(
                repository,
                authority,
                git_bin,
                "-c",
                "user.name=Nix NAS",
                "-c",
                "user.email=nix-nas@localhost",
                "commit",
                "--no-gpg-sign",
                "--message",
                message,
                "--",
                relative,
            )
        head = _rev_parse(repository, authority, git_bin, "HEAD")
        if head is None:
            raise DesiredStateHistoryError("history repository has no desired-state commit after record")
    return {"ok": True, "changed": changed, "head": head, "authority": str(authority)}


def mark_applied(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
    commit: str | None = None,
) -> dict[str, Any]:
    """Advance the last-known-good ref after runtime reconciliation succeeds."""
    ensure_repository(authority=authority, repository=repository, git_bin=git_bin)
    desired = commit or _rev_parse(repository, authority, git_bin, "HEAD")
    if desired is None:
        raise DesiredStateHistoryError("cannot mark applied state before desired state has been committed")
    verified = _rev_parse(repository, authority, git_bin, desired)
    if verified is None:
        raise DesiredStateHistoryError(f"cannot mark unknown Git object as applied: {desired}")
    old = _rev_parse(repository, authority, git_bin, APPLIED_REF)
    command = ["update-ref", APPLIED_REF, verified]
    if old is not None:
        command.append(old)
    _git(repository, authority, git_bin, *command)
    return {"ok": True, "applied": verified, "previousApplied": old}


def restore_applied(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
    message: str = "Automatic rollback to last applied Managed Services V2 state",
) -> dict[str, Any]:
    """Restore ``services.yaml`` from ``refs/nas/applied`` and record the rollback."""
    with _authority_lock(authority):
        ensure_repository(authority=authority, repository=repository, git_bin=git_bin)
        applied = _rev_parse(repository, authority, git_bin, APPLIED_REF)
        if applied is None:
            raise DesiredStateHistoryError("no last-applied desired-state revision exists")
        relative = authority.name
        _git(
            repository,
            authority,
            git_bin,
            "restore",
            f"--source={applied}",
            "--staged",
            "--worktree",
            "--",
            relative,
        )
        diff = _git(repository, authority, git_bin, "diff", "--cached", "--quiet", "--", relative, check=False)
        if diff.returncode not in {0, 1}:
            detail = (diff.stderr or diff.stdout).strip()[:4000]
            raise DesiredStateHistoryError(f"unable to compare restored desired state: {detail}")
        changed = diff.returncode == 1
        if changed:
            _git(
                repository,
                authority,
                git_bin,
                "-c",
                "user.name=Nix NAS",
                "-c",
                "user.email=nix-nas@localhost",
                "commit",
                "--no-gpg-sign",
                "--message",
                message,
                "--",
                relative,
            )
        head = _rev_parse(repository, authority, git_bin, "HEAD")
    return {"ok": True, "changed": changed, "restoredFrom": applied, "head": head}


def history_status(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
) -> dict[str, Any]:
    if not repository.exists():
        return {"ok": True, "initialized": False, "desired": None, "applied": None}
    desired = _rev_parse(repository, authority, git_bin, "HEAD")
    applied = _rev_parse(repository, authority, git_bin, APPLIED_REF)
    return {
        "ok": True,
        "initialized": True,
        "desired": desired,
        "applied": applied,
        "inSync": desired is not None and desired == applied,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage Git history for Managed Services V2 desired state")
    parser.add_argument("--authority", default=str(DEFAULT_AUTHORITY))
    parser.add_argument("--repository", default=str(DEFAULT_REPOSITORY))
    parser.add_argument("--git-bin", default="git")
    subparsers = parser.add_subparsers(dest="command", required=True)
    record = subparsers.add_parser("record")
    record.add_argument("--message", default="Update Managed Services V2 desired state")
    applied = subparsers.add_parser("mark-applied")
    applied.add_argument("--commit", default=None)
    restore = subparsers.add_parser("restore-applied")
    restore.add_argument("--message", default="Automatic rollback to last applied Managed Services V2 state")
    subparsers.add_parser("status")
    args = parser.parse_args(argv)

    authority = pathlib.Path(args.authority)
    repository = pathlib.Path(args.repository)
    try:
        if args.command == "record":
            result = record_desired(
                authority=authority,
                repository=repository,
                git_bin=args.git_bin,
                message=args.message,
            )
        elif args.command == "mark-applied":
            result = mark_applied(
                authority=authority,
                repository=repository,
                git_bin=args.git_bin,
                commit=args.commit,
            )
        elif args.command == "restore-applied":
            result = restore_applied(
                authority=authority,
                repository=repository,
                git_bin=args.git_bin,
                message=args.message,
            )
        else:
            result = history_status(authority=authority, repository=repository, git_bin=args.git_bin)
    except DesiredStateHistoryError as exc:
        print(f"nas-v2-history: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = [
    "APPLIED_REF",
    "DEFAULT_AUTHORITY",
    "DEFAULT_REPOSITORY",
    "DesiredStateHistoryError",
    "ensure_repository",
    "history_status",
    "mark_applied",
    "record_desired",
    "restore_applied",
]


if __name__ == "__main__":
    raise SystemExit(main())
