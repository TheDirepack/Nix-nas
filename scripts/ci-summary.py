from __future__ import annotations

import json
import os
import sys
from typing import Any


PREBUILD_JOBS = {"prebuild"}
PREPARE_JOBS = {"prepare"}
QUALIFICATION_JOBS = {"browser", "integration"}
SLOW_JOBS = {"source-fuzz"}
INSTALLED_SECURITY_JOBS = {"installed-security"}
KNOWN_JOBS = frozenset(
    PREBUILD_JOBS
    | PREPARE_JOBS
    | QUALIFICATION_JOBS
    | SLOW_JOBS
    | INSTALLED_SECURITY_JOBS
    | {"coverage-diff", "installer"}
)


def _main_or_release_ref(ref: str) -> bool:
    return ref == "refs/heads/main" or ref.startswith("refs/tags/v")


def expected_jobs(event_name: str, ref: str, base_ref: str, test_tier: str) -> set[str]:
    # Every run qualifies source/configuration, prepares the exact Cockpit
    # product, and runs the deterministic browser suite. The explicit fast
    # dispatch tier skips only the expensive Nix/VM work inside prepare.
    expected = set(PREBUILD_JOBS | PREPARE_JOBS | {"browser"})

    if event_name == "pull_request" and base_ref == "main":
        expected.add("coverage-diff")

    qualification_run = (
        event_name == "schedule"
        or (event_name == "push" and _main_or_release_ref(ref))
        or (event_name == "workflow_dispatch" and test_tier in {"full", "installer"})
    )
    if qualification_run:
        expected.add("integration")

    installer_run = (event_name == "workflow_dispatch" and test_tier in {"full", "installer"}) or (
        event_name != "workflow_dispatch" and _main_or_release_ref(ref)
    )
    if installer_run:
        expected.add("installer")

    release_qualification = event_name == "schedule" or (
        event_name == "push" and _main_or_release_ref(ref)
    )
    if release_qualification:
        expected.update(SLOW_JOBS | INSTALLED_SECURITY_JOBS)

    return expected


def summarize(
    needs: dict[str, Any],
    event_name: str,
    ref: str,
    base_ref: str,
    test_tier: str,
) -> tuple[str, list[str]]:
    expected = expected_jobs(event_name, ref, base_ref, test_tier)
    lines = ["## CI pipeline summary", "", "| Stage | Result |", "| --- | --- |"]
    bad: list[str] = []

    for name, data in sorted(needs.items()):
        result = data.get("result", "skipped") if isinstance(data, dict) else "skipped"
        lines.append(f"| {name} | {result.upper()} |")
        if name in expected and result != "success":
            bad.append(f"{name}={result} (required)")
        elif result in {"failure", "cancelled"}:
            bad.append(f"{name}={result}")

    missing = sorted(expected - set(needs))
    bad.extend(f"{name}=missing (required)" for name in missing)
    return "\n".join(lines) + "\n", bad


def main() -> int:
    needs = json.loads(os.environ["NEEDS_JSON"])
    if not isinstance(needs, dict):
        raise SystemExit("NEEDS_JSON must be an object")
    summary, bad = summarize(
        needs,
        os.environ.get("EVENT_NAME", ""),
        os.environ.get("REF", ""),
        os.environ.get("BASE_REF", ""),
        os.environ.get("TEST_TIER", "fast"),
    )
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(summary)
    else:
        sys.stdout.write(summary)
    if bad:
        print("pipeline qualification incomplete: " + ", ".join(bad), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
