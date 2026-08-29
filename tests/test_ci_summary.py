from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_summary",
    ROOT / "scripts" / "ci-summary.py",
)
assert SPEC and SPEC.loader
ci_summary = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ci_summary
SPEC.loader.exec_module(ci_summary)


class CiSummaryTests(unittest.TestCase):
    def results(self, expected: set[str]) -> dict[str, dict[str, str]]:
        return {name: {"result": "success" if name in expected else "skipped"} for name in ci_summary.KNOWN_JOBS}

    def test_summary_policy_classifies_every_workflow_dependency(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        summary = workflow.split("  summary:\n", 1)[1]
        match = re.search(r"^    needs: \[([^]]+)]$", summary, re.MULTILINE)
        self.assertIsNotNone(match)
        assert match is not None
        workflow_jobs = {name.strip() for name in match.group(1).split(",")}
        self.assertEqual(workflow_jobs, set(ci_summary.KNOWN_JOBS))
        self.assertNotIn(".ci-cache/", workflow)

    def test_pull_request_runs_full_stack_installer_and_browser(self) -> None:
        expected = ci_summary.expected_jobs(
            "pull_request",
            "refs/pull/40/merge",
            "main",
            "fast",
        )
        self.assertEqual(
            expected,
            set(ci_summary.BASE_JOBS) | {"coverage-diff", "integration", "installer"},
        )
        _, bad = ci_summary.summarize(
            self.results(expected),
            "pull_request",
            "refs/pull/40/merge",
            "main",
            "fast",
        )
        self.assertEqual(bad, [])

    def test_non_main_pull_request_skips_main_coverage_baseline(self) -> None:
        expected = ci_summary.expected_jobs(
            "pull_request",
            "refs/pull/40/merge",
            "release",
            "fast",
        )
        self.assertEqual(expected, set(ci_summary.BASE_JOBS) | {"integration", "installer"})

    def test_fast_dispatch_keeps_parallel_qualification_and_browser(self) -> None:
        expected = ci_summary.expected_jobs(
            "workflow_dispatch",
            "refs/heads/main",
            "",
            "fast",
        )
        self.assertEqual(expected, set(ci_summary.BASE_JOBS))
        _, bad = ci_summary.summarize(
            self.results(expected),
            "workflow_dispatch",
            "refs/heads/main",
            "",
            "fast",
        )
        self.assertEqual(bad, [])

    def test_full_dispatch_adds_integration_installer_and_manual_fuzz(self) -> None:
        expected = ci_summary.expected_jobs(
            "workflow_dispatch",
            "refs/heads/main",
            "",
            "full",
        )
        self.assertEqual(
            expected,
            set(ci_summary.BASE_JOBS) | {"integration", "installer", "source-fuzz"},
        )
        self.assertNotIn("installed-security", expected)
        installer_dispatch = ci_summary.expected_jobs(
            "workflow_dispatch",
            "refs/heads/main",
            "",
            "installer",
        )
        self.assertEqual(
            installer_dispatch,
            set(ci_summary.BASE_JOBS) | {"integration", "installer"},
        )
        self.assertNotIn("source-fuzz", installer_dispatch)

    def test_main_push_runs_complete_release_qualification(self) -> None:
        expected = ci_summary.expected_jobs("push", "refs/heads/main", "", "fast")
        self.assertEqual(
            expected,
            set(ci_summary.BASE_JOBS)
            | {
                "integration",
                "installer",
                "installed-security",
            },
        )
        # Long fuzz searches are manual-only and never ride along with
        # automatic events.
        self.assertNotIn("source-fuzz", expected)

    def test_any_reported_failure_is_rejected_even_when_job_is_optional(self) -> None:
        expected = ci_summary.expected_jobs(
            "workflow_dispatch",
            "refs/heads/topic",
            "",
            "fast",
        )
        needs = self.results(expected)
        needs["installer"]["result"] = "failure"
        _, bad = ci_summary.summarize(
            needs,
            "workflow_dispatch",
            "refs/heads/topic",
            "",
            "fast",
        )
        self.assertIn("installer=failure", bad)


if __name__ == "__main__":
    unittest.main()
