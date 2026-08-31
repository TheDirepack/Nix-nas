"""Summarize independent CI outcomes and surface actionable failure context."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from dataclasses import dataclass


GOOD = {"success", "skipped"}
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass(frozen=True)
class Check:
    name: str
    outcome: str


@dataclass(frozen=True)
class Subcheck:
    section: str
    slug: str
    name: str
    exit_code: int
    elapsed_seconds: int
    log_path: pathlib.Path
    command: str

    @property
    def failed(self) -> bool:
        return self.exit_code != 0


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


def parse_results(path: pathlib.Path) -> list[Subcheck]:
    if not path.is_file():
        raise ValueError(f"subcheck results file does not exist: {path}")

    results: list[Subcheck] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw:
            continue
        fields = raw.split("\t", 6)
        if len(fields) != 7:
            raise ValueError(f"{path}:{line_number}: expected 7 tab-separated fields")
        section, slug, name, exit_text, elapsed_text, log_text, command = fields
        try:
            exit_code = int(exit_text)
            elapsed_seconds = int(elapsed_text)
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: exit code and elapsed time must be integers") from exc
        if not section or not slug or not name or not log_text or not command:
            raise ValueError(f"{path}:{line_number}: required field is empty")
        if exit_code < 0 or elapsed_seconds < 0:
            raise ValueError(f"{path}:{line_number}: numeric fields must be non-negative")
        results.append(
            Subcheck(
                section=section,
                slug=slug,
                name=name,
                exit_code=exit_code,
                elapsed_seconds=elapsed_seconds,
                log_path=pathlib.Path(log_text),
                command=command,
            )
        )
    return results


def failed_checks(checks: list[Check]) -> list[Check]:
    return [check for check in checks if check.outcome not in GOOD]


def failed_subchecks(results: list[Subcheck]) -> list[Subcheck]:
    return [result for result in results if result.failed]


def _clean_log_line(line: str) -> str:
    return ANSI_RE.sub("", line).replace("```", "` ` `")


def log_tail(result: Subcheck, tail_lines: int) -> list[str]:
    if tail_lines < 1:
        raise ValueError("tail_lines must be positive")
    try:
        lines = result.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [f"Unable to read {result.log_path}: {exc}"]
    tail = lines[-tail_lines:]
    return [_clean_log_line(line)[:600] for line in tail]


def render_summary(
    title: str,
    checks: list[Check],
    results: list[Subcheck] | None = None,
    *,
    tail_lines: int = 25,
) -> str:
    lines = [f"## {title}", "", "| Section | Result |", "| --- | --- |"]
    for check in checks:
        lines.append(f"| {check.name} | {check.outcome.upper()} |")

    if results is not None:
        failures = failed_subchecks(results)
        passed = len(results) - len(failures)
        lines.extend(
            [
                "",
                f"Subchecks: **{passed} passed**, **{len(failures)} failed**.",
            ]
        )
        if failures:
            lines.extend(["", "### Failed subchecks"])
            for result in failures:
                lines.extend(
                    [
                        "",
                        f"#### {result.name}",
                        "",
                        (
                            f"Section `{result.section}` · exit `{result.exit_code}` · "
                            f"{result.elapsed_seconds}s · log `{result.log_path}`"
                        ),
                        "",
                        f"Command: `{result.command}`",
                        "",
                        "```text",
                        *log_tail(result, tail_lines),
                        "```",
                    ]
                )
        elif results:
            lines.extend(["", f"All {len(results)} recorded subchecks passed."])
    return "\n".join(lines) + "\n"


def _annotation_text(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit_failure_annotations(title: str, checks: list[Check], results: list[Subcheck]) -> None:
    failed_sections = {check.name for check in failed_checks(checks)}
    detailed_sections: set[str] = set()
    for result in failed_subchecks(results):
        detailed_sections.add(result.section)
        message = (
            f"exit {result.exit_code} after {result.elapsed_seconds}s; "
            f"command: {result.command}; full log: {result.log_path}"
        )
        print(
            f"::error title={_annotation_text(result.name)}::{_annotation_text(message)}",
            flush=True,
        )

    for section in sorted(failed_sections - detailed_sections):
        print(
            f"::error title={_annotation_text(title)}::"
            f"{_annotation_text(section)} failed without a recorded subcheck log",
            flush=True,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        type=pathlib.Path,
        help="optional TSV produced by .github/ci-checks.sh",
    )
    parser.add_argument(
        "--tail-lines",
        type=int,
        default=25,
        help="number of trailing log lines to include for each failed subcheck",
    )
    parser.add_argument("checks", nargs="+", metavar="NAME=OUTCOME")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    title = os.environ.get("CI_REPORT_TITLE", "CI check summary")
    try:
        checks = parse_checks(args.checks)
        results = parse_results(args.results) if args.results else []
        summary = render_summary(
            title,
            checks,
            results if args.results else None,
            tail_lines=args.tail_lines,
        )
    except ValueError as exc:
        print(f"ci-check-report: {exc}", file=sys.stderr)
        return 2

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(summary)
    else:
        sys.stdout.write(summary)

    section_failures = failed_checks(checks)
    subcheck_failures = failed_subchecks(results)
    emit_failure_annotations(title, checks, results)
    if section_failures or subcheck_failures:
        section_names = ", ".join(f"{check.name}={check.outcome}" for check in section_failures)
        print(
            f"{title} failed: {section_names or 'recorded subcheck failure'}",
            file=sys.stderr,
        )
        return 1

    print(f"{title} passed: {len(checks)} section(s), {len(results)} subcheck(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
