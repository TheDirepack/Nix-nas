#!/usr/bin/env python3
"""Summarize independent CI check outcomes and fail once at the end."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Check:
    name: str
    outcome: str


GOOD = {"success", "skipped"}


def parse_checks(values: list[str]) -> list[Check]:
    checks: list[Check] = []
    for value in values:
        name, separator, outcome = value.partition("=")
        if not separator or not name or not outcome:
            raise ValueError(f"invalid check outcome {value!r}; expected name=outcome")
        checks.append(Check(name=name, outcome=outcome))
    if not checks:
        raise ValueError("at least one check outcome is required")
    return checks


def render_summary(title: str, checks: list[Check]) -> str:
    lines = [f"## {title}", "", "| Section | Result |", "| --- | --- |"]
    for check in checks:
        lines.append(f"| {check.name} | {check.outcome.upper()} |")
    return "\n".join(lines) + "\n"


def failed_checks(checks: list[Check]) -> list[Check]:
    return [check for check in checks if check.outcome not in GOOD]


def main() -> int:
    title = os.environ.get("CI_REPORT_TITLE", "CI check summary")
    try:
        checks = parse_checks(sys.argv[1:])
    except ValueError as exc:
        print(f"ci-check-report: {exc}", file=sys.stderr)
        return 2

    summary = render_summary(title, checks)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(summary)
    else:
        sys.stdout.write(summary)

    failures = failed_checks(checks)
    for check in failures:
        print(
            f"::error title={title}::{check.name} finished with {check.outcome}",
            flush=True,
        )
    if failures:
        names = ", ".join(f"{check.name}={check.outcome}" for check in failures)
        print(f"{title} failed: {names}", file=sys.stderr)
        return 1

    print(f"{title} passed: {len(checks)} section(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
