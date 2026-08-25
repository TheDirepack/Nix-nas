#!/usr/bin/env python3
"""Git-backed history for the Managed Services V2 desired-state authority.

Git is the durable history and rollback store for ``services.yaml``. Runtime
subsystems remain projections of that file; this module deliberately tracks no
generated state and no second desired-state database.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
from typing import Any, Sequence

from nas_v2_editor import authority_lock

DEFAULT_AUTHORITY = pathlib.Path("/var/lib/nas-control/services.yaml")
DEFAULT_REPOSITORY = pathlib.Path("/var/lib/nas-control/config-history.git")
APPLIED_REF = "refs/nas/applied"
DESIRED_REF = "refs/heads/main"
_BOOTSTRAP_BASELINE = b"schemaVersion: 3\nservices: {}\n"


class DesiredStateHistoryError(RuntimeError):
    """Raised when desired-state history cannot be updated safely."""


def _run(
    command: Sequence[str],
    *,
    check: bool = True,
    timeout: int = 30,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        run_kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "timeout": timeout,
            "check": False,
        }
        if input_text is None:
            run_kwargs["stdin"] = subprocess.DEVNULL
        else:
            run_kwargs["input"] = input_text
        result = subprocess.run(list(command), **run_kwargs)
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
        _run([git_bin, "init", "--bare", str(repository)])
        _git(repository, authority, git_bin, "symbolic-ref", "HEAD", DESIRED_REF)
    try:
        os.chmod(repository, 0o750)
    except OSError:
        pass


def _bootstrap_baseline_locked(
    *,
    authority: pathlib.Path,
    repository: pathlib.Path,
    git_bin: str,
) -> dict[str, Any]:
    """Create the truthful empty V2 state used before the first mutation.

    A first desired revision cannot be its own rollback target: doing so would
    simply compile the failed configuration again.  The empty V3 document is
    the native V2 baseline before any managed application/network/firewall
    projection exists, so it is committed as the parent of the first desired
    revision and selected as ``refs/nas/applied``.
    """
    ensure_repository(authority=authority, repository=repository, git_bin=git_bin)
    if _rev_parse(repository, authority, git_bin, APPLIED_REF) is not None:
        return {"ok": True, "created": False, "applied": _rev_parse(repository, authority, git_bin, APPLIED_REF)}
    if _rev_parse(repository, authority, git_bin, DESIRED_REF) is not None:
        raise DesiredStateHistoryError(
            "history has desired revisions but no applied revision; refusing to invent a first-boot rollback target"
        )

    blob = _run(
        [git_bin, f"--git-dir={repository}", "hash-object", "-w", "--stdin"],
        input_text=_BOOTSTRAP_BASELINE.decode("utf-8"),
    ).stdout.strip()
    tree = _run(
        [git_bin, f"--git-dir={repository}", "mktree"],
        input_text=f"100640 blob {blob}\t{authority.name}\n",
    ).stdout.strip()
    commit = _run(
        [
            git_bin,
            "-c",
            "user.name=Nix NAS",
            "-c",
            "user.email=nix-nas@localhost",
            f"--git-dir={repository}",
            "commit-tree",
            tree,
            "-m",
            "Managed Services V2 bootstrap baseline",
        ],
    ).stdout.strip()
    if not commit:
        raise DesiredStateHistoryError("Git did not return a bootstrap baseline revision")
    _git(repository, authority, git_bin, "update-ref", DESIRED_REF, commit)
    _git(repository, authority, git_bin, "update-ref", APPLIED_REF, commit)
    return {"ok": True, "created": True, "applied": commit}


def ensure_bootstrap_applied(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
) -> dict[str, Any]:
    """Ensure first-ever reconciliation has an actual pre-mutation target."""
    with authority_lock(authority):
        return _bootstrap_baseline_locked(authority=authority, repository=repository, git_bin=git_bin)


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


def _authority_matches_commit_locked(
    *,
    authority: pathlib.Path,
    repository: pathlib.Path,
    git_bin: str,
    commit: str,
) -> bool:
    """Compare the locked authority worktree file with one committed revision."""
    verified = _rev_parse(repository, authority, git_bin, commit)
    if verified is None:
        raise DesiredStateHistoryError(f"unknown desired-state Git revision: {commit}")
    relative = authority.name
    result = _git(
        repository, authority, git_bin, "diff", "--quiet", "--exit-code", verified, "--", relative, check=False
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    detail = (result.stderr or result.stdout).strip()[:4000]
    raise DesiredStateHistoryError(f"unable to compare authority with {verified}: {detail}")


def authority_matches_commit(
    *,
    commit: str,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
) -> bool:
    """Return whether the current authority still equals ``commit``."""
    with authority_lock(authority):
        ensure_repository(authority=authority, repository=repository, git_bin=git_bin)
        return _authority_matches_commit_locked(
            authority=authority,
            repository=repository,
            git_bin=git_bin,
            commit=commit,
        )


def record_desired_locked(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
    message: str = "Update Managed Services V2 desired state",
) -> dict[str, Any]:
    """Commit the exact authority file while the caller holds its authority lock."""
    if authority.parent == authority:
        raise DesiredStateHistoryError("desired-state authority has no parent work tree")
    if not authority.is_file():
        raise DesiredStateHistoryError(f"desired-state authority is missing: {authority}")
    if not message.strip():
        raise DesiredStateHistoryError("history commit message must not be empty")

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


def record_desired(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
    message: str = "Update Managed Services V2 desired state",
) -> dict[str, Any]:
    """Commit the exact authority file if its contents changed."""
    with authority_lock(authority):
        return record_desired_locked(
            authority=authority,
            repository=repository,
            git_bin=git_bin,
            message=message,
        )


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


def acknowledge_pending(
    *,
    commit: str,
    pending: pathlib.Path,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
) -> dict[str, Any]:
    """Clear the level-triggered reconcile marker only for the current authority."""
    with authority_lock(authority):
        ensure_repository(authority=authority, repository=repository, git_bin=git_bin)
        current = _authority_matches_commit_locked(
            authority=authority,
            repository=repository,
            git_bin=git_bin,
            commit=commit,
        )
        if current:
            try:
                pending.unlink(missing_ok=True)
            except OSError as exc:
                raise DesiredStateHistoryError(f"unable to clear reconcile marker {pending}: {exc}") from exc
    return {"ok": True, "current": current, "pending": str(pending), "commit": commit}


def restore_applied(
    *,
    authority: pathlib.Path = DEFAULT_AUTHORITY,
    repository: pathlib.Path = DEFAULT_REPOSITORY,
    git_bin: str = "git",
    message: str = "Automatic rollback to last applied Managed Services V2 state",
    failed_commit: str | None = None,
) -> dict[str, Any]:
    """Restore the last applied revision unless a newer desired edit superseded the failure."""
    with authority_lock(authority):
        ensure_repository(authority=authority, repository=repository, git_bin=git_bin)
        applied = _rev_parse(repository, authority, git_bin, APPLIED_REF)
        if applied is None:
            raise DesiredStateHistoryError("no last-applied desired-state revision exists")
        if failed_commit is not None and not _authority_matches_commit_locked(
            authority=authority,
            repository=repository,
            git_bin=git_bin,
            commit=failed_commit,
        ):
            return {
                "ok": True,
                "changed": False,
                "superseded": True,
                "failedCommit": failed_commit,
                "restoredFrom": None,
                "applied": applied,
                "head": _rev_parse(repository, authority, git_bin, "HEAD"),
            }

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
    return {
        "ok": True,
        "changed": changed,
        "superseded": False,
        "failedCommit": failed_commit,
        "restoredFrom": applied,
        "head": head,
    }


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
    restore.add_argument("--failed-commit", default=None)
    acknowledge = subparsers.add_parser("ack-pending")
    acknowledge.add_argument("--commit", required=True)
    acknowledge.add_argument("--pending", required=True)
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
                failed_commit=args.failed_commit,
            )
        elif args.command == "ack-pending":
            result = acknowledge_pending(
                authority=authority,
                repository=repository,
                git_bin=args.git_bin,
                commit=args.commit,
                pending=pathlib.Path(args.pending),
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
    "acknowledge_pending",
    "authority_matches_commit",
    "ensure_bootstrap_applied",
    "ensure_repository",
    "history_status",
    "mark_applied",
    "record_desired",
    "record_desired_locked",
    "restore_applied",
]


if __name__ == "__main__":
    raise SystemExit(main())
