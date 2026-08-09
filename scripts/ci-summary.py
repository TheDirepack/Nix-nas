from __future__ import annotations

import json
import os
import sys
from typing import Any


FAST_JOBS = {
    "test",
    "test-nonroot",
    "security",
    "caddy-validate",
    "static",
    "dependency-audit",
}
HEAVY_JOBS = {"build", "browser", "integration"}
SLOW_JOBS = {"fuzz", "browser-fuzz"}
KNOWN_JOBS = frozenset(FAST_JOBS | HEAVY_JOBS | SLOW_JOBS | {"coverage-diff", "installer"})


def expected_jobs(event_name: str, ref: str, base_ref: str, test_tier: str) -> set[str]:
    expected = set(FAST_JOBS)
    if event_name == "pull_request" and base_ref == "main":
        expected.add("coverage-diff")
    if event_name != "workflow_dispatch" or test_tier != "fast":
        expected.update(HEAVY_JOBS)
    if (event_name == "workflow_dispatch" and test_tier == "installer") or (
        event_name != "workflow_dispatch" and (ref == "refs/heads/main" or ref.startswith("refs/tags/v"))
    ):
        expected.add("installer")
    if (
        event_name == "pull_request"
        or (event_name != "workflow_dispatch" and (ref == "refs/heads/main" or ref.startswith("refs/tags/v")))
        or (event_name == "workflow_dispatch" and test_tier in {"full", "installer"})
    ):
        expected.update(SLOW_JOBS)
    return expected


def summarize(needs: dict[str, Any], event_name: str, ref: str, base_ref: str, test_tier: str) -> tuple[str, list[str]]:
    expected = expected_jobs(event_name, ref, base_ref, test_tier)
    lines = ["## CI pipeline summary", "", "| Job | Result |", "| --- | --- |"]
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
