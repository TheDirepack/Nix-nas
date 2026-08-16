from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ci_summary", ROOT / "scripts" / "ci-summary.py")
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

    def test_heavy_jobs_match_the_consolidated_build_graph(self) -> None:
        self.assertEqual({"build"}, ci_summary.HEAVY_JOBS)
        self.assertEqual({"browser", "integration"}, ci_summary.QUALIFICATION_JOBS)

    def test_pull_request_requires_fast_build_and_browser_but_not_destructive_qualification(self) -> None:
        expected = ci_summary.expected_jobs("pull_request", "refs/pull/25/merge", "main", "fast")
        needs = self.results(expected)
        _, bad = ci_summary.summarize(needs, "pull_request", "refs/pull/25/merge", "main", "fast")
        self.assertEqual(bad, [])

        self.assertIn("browser", expected)
        self.assertNotIn("integration", expected)
        self.assertNotIn("source-fuzz", expected)

    def test_non_main_pull_request_does_not_require_main_coverage_baseline(self) -> None:
        expected = ci_summary.expected_jobs("pull_request", "refs/pull/25/merge", "release", "fast")
        self.assertNotIn("coverage-diff", expected)

    def test_fast_dispatch_runs_deterministic_browser_checks_but_skips_heavy_jobs(self) -> None:
        expected = ci_summary.expected_jobs("workflow_dispatch", "refs/heads/main", "", "fast")
        self.assertEqual(expected, ci_summary.FAST_JOBS | {"browser"})
        _, bad = ci_summary.summarize(
            self.results(expected),
            "workflow_dispatch",
            "refs/heads/main",
            "",
            "fast",
        )
        self.assertEqual(bad, [])

    def test_full_dispatch_includes_installer_and_installed_vm_checks(self) -> None:
        full = ci_summary.expected_jobs("workflow_dispatch", "refs/heads/main", "", "full")
        installer = ci_summary.expected_jobs("workflow_dispatch", "refs/heads/main", "", "installer")
        self.assertTrue(ci_summary.HEAVY_JOBS | ci_summary.QUALIFICATION_JOBS | ci_summary.SLOW_JOBS <= full)
        self.assertIn("installer", full)
        self.assertTrue(ci_summary.INSTALLED_FUZZ_JOBS <= full)
        self.assertIn("installer", installer)
        self.assertTrue(ci_summary.INSTALLED_FUZZ_JOBS <= installer)

    def test_any_reported_failure_is_rejected_even_when_job_is_optional(self) -> None:
        expected = ci_summary.expected_jobs("workflow_dispatch", "refs/heads/topic", "", "fast")
        needs = self.results(expected)
        needs["installer"]["result"] = "failure"
        _, bad = ci_summary.summarize(needs, "workflow_dispatch", "refs/heads/topic", "", "fast")
        self.assertIn("installer=failure", bad)

    def test_cache_persistence_failure_is_reported_without_blocking_qualification(self) -> None:
        expected = ci_summary.expected_jobs("pull_request", "refs/pull/25/merge", "main", "fast")
        needs = self.results(expected)
        needs["cache-vm-bundles"] = {"result": "failure"}
        summary, bad = ci_summary.summarize(needs, "pull_request", "refs/pull/25/merge", "main", "fast")
        self.assertEqual(bad, [])
        self.assertIn("cache-vm-bundles=failure", summary)
        self.assertIn("non-authoritative cache persistence warning", summary)


if __name__ == "__main__":
    unittest.main()
