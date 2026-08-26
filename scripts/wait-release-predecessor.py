#!/usr/bin/env python3
"""Wait until an earlier qualified main merge is released before this source.

GitHub concurrency queues preserve queue-entry order, not source-history order.
Main CI runs can finish out of order, so release publication needs an explicit
source-order barrier. This helper uses Git first-parent history plus GitHub's
recorded PR merge result and CI runs to find the nearest earlier source that is
still entitled to an automated release.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTIVE_RUN_STATUSES = {"queued", "in_progress", "pending", "requested", "waiting"}


def run(
    *args: str,
    cwd: pathlib.Path = ROOT,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
    )


def git(*args: str, cwd: pathlib.Path = ROOT, check: bool = True) -> str:
    return run("git", *args, cwd=cwd, check=check).stdout.strip()


def gh_json(endpoint: str) -> Any:
    result = run("gh", "api", "-H", "Accept: application/vnd.github+json", endpoint)
    return json.loads(result.stdout)


def exact_main_merge_result(prs: Any, source_sha: str) -> bool:
    if not isinstance(prs, list):
        raise RuntimeError("GitHub commit/pulls response must be a JSON array")
    return any(
        isinstance(pr, dict)
        and pr.get("merged_at") is not None
        and isinstance(pr.get("base"), dict)
        and pr["base"].get("ref") == "main"
        and pr.get("merge_commit_sha") == source_sha
        for pr in prs
    )


def classify_ci_runs(payload: Any) -> str:
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
        raise RuntimeError("GitHub workflow-runs response is malformed")
    runs = [run for run in payload["workflow_runs"] if isinstance(run, dict)]
    if any(run.get("conclusion") == "success" for run in runs):
        return "success"
    if any(run.get("status") in ACTIVE_RUN_STATUSES for run in runs):
        return "active"
    return "not-qualified"


def release_sources(root: pathlib.Path) -> dict[str, str]:
    """Return generated release tag -> main source parent for local tags."""
    sources: dict[str, str] = {}
    for tag in git("tag", "--list", "v*", cwd=root).splitlines():
        tag = tag.strip()
        if not tag:
            continue
        parent = run(
            "git",
            "rev-parse",
            f"{tag}^{{commit}}^1",
            cwd=root,
            check=False,
        )
        if parent.returncode == 0:
            sources[tag] = parent.stdout.strip()
    return sources


def is_ancestor(root: pathlib.Path, older: str, newer: str) -> bool:
    result = run("git", "merge-base", "--is-ancestor", older, newer, cwd=root, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "git merge-base failed")
    return result.returncode == 0


def fetch_tags(root: pathlib.Path) -> None:
    run("git", "fetch", "--force", "--tags", "origin", cwd=root)


def tag_for_source(root: pathlib.Path, source_sha: str) -> str | None:
    for tag, tagged_source in release_sources(root).items():
        if tagged_source == source_sha:
            return tag
    return None


def reject_published_descendant(root: pathlib.Path, source_sha: str) -> None:
    for tag, tagged_source in release_sources(root).items():
        if tagged_source != source_sha and is_ancestor(root, source_sha, tagged_source):
            raise RuntimeError(
                f"refusing to publish older source {source_sha}: {tag} already publishes "
                f"descendant source {tagged_source}"
            )


def first_parent_ancestors(root: pathlib.Path, source_sha: str) -> list[str]:
    parent = git("rev-parse", f"{source_sha}^1", cwd=root, check=False)
    if not parent:
        return []
    output = git("rev-list", "--first-parent", parent, cwd=root)
    return [line for line in output.splitlines() if line]


def commit_is_exact_main_merge(repository: str, source_sha: str) -> bool:
    prs = gh_json(f"/repos/{repository}/commits/{source_sha}/pulls")
    return exact_main_merge_result(prs, source_sha)


def ci_state(repository: str, workflow: str, source_sha: str) -> str:
    endpoint = (
        f"/repos/{repository}/actions/workflows/{workflow}/runs"
        f"?event=push&branch=main&head_sha={source_sha}&per_page=20"
    )
    return classify_ci_runs(gh_json(endpoint))


def find_predecessor_state(
    root: pathlib.Path,
    repository: str,
    workflow: str,
    source_sha: str,
) -> tuple[str | None, str]:
    """Return nearest earlier exact main merge that may still require release."""
    for ancestor in first_parent_ancestors(root, source_sha):
        if not commit_is_exact_main_merge(repository, ancestor):
            continue
        state = ci_state(repository, workflow, ancestor)
        if state == "not-qualified":
            # A completed failed/cancelled source is not automatically
            # backfilled after descendants move on. If it is manually rerun
            # later, reject_published_descendant() prevents source regression.
            continue
        return ancestor, state
    return None, "none"


def wait_for_predecessor(
    root: pathlib.Path,
    repository: str,
    source_sha: str,
    *,
    workflow: str,
    poll_seconds: int,
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        fetch_tags(root)
        reject_published_descendant(root, source_sha)
        predecessor, state = find_predecessor_state(root, repository, workflow, source_sha)
        if predecessor is None:
            print(f"release ordering ready: no earlier qualified merge blocks {source_sha}")
            return

        existing_tag = tag_for_source(root, predecessor)
        if state == "success" and existing_tag is not None:
            print(
                f"release ordering ready: predecessor {predecessor} is published as {existing_tag}"
            )
            return

        if time.monotonic() >= deadline:
            if state == "success":
                reason = "qualified successfully but has no release tag"
            else:
                reason = f"CI is still {state}"
            raise TimeoutError(
                f"timed out waiting for predecessor {predecessor}: {reason}"
            )

        if state == "success":
            detail = "successful CI; waiting for release tag"
        else:
            detail = f"CI {state}; waiting for qualification to finish"
        print(f"release ordering blocked by {predecessor}: {detail}", flush=True)
        time.sleep(poll_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--workflow", default="ci.yml")
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--timeout-seconds", type=int, default=19_800)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.poll_seconds < 1 or args.timeout_seconds < 1:
        raise SystemExit("poll and timeout values must be positive")
    if not os.environ.get("GH_TOKEN"):
        raise SystemExit("GH_TOKEN is required to inspect GitHub merge/CI state")
    wait_for_predecessor(
        args.root.resolve(),
        args.repository,
        args.source_sha,
        workflow=args.workflow,
        poll_seconds=args.poll_seconds,
        timeout_seconds=args.timeout_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
