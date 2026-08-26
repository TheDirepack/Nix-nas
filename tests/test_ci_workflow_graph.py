from __future__ import annotations

import pathlib
import unittest
from typing import Any

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
HANDOFF_ACTION = ROOT / ".github" / "actions" / "prepare-vm-handoff" / "action.yml"


class CiWorkflowGraphTests(unittest.TestCase):
    BUNDLES = ("core", "identity", "observability", "storage", "ai", "vm-drivers")
    JOBS = {
        "prebuild",
        "coverage-diff",
        "prepare",
        "browser",
        "integration",
        "installer",
        "source-fuzz",
        "installed-security",
        "summary",
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        cls.jobs = cls.workflow["jobs"]
        cls.handoff = yaml.load(HANDOFF_ACTION.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    @staticmethod
    def needs(job: dict[str, Any]) -> set[str]:
        value = job.get("needs", [])
        if isinstance(value, list):
            return {str(item) for item in value}
        return {str(value)}

    @staticmethod
    def serialized(value: Any) -> str:
        return repr(value)

    @staticmethod
    def run_text(job: dict[str, Any]) -> str:
        return "\n".join(
            str(step.get("run", ""))
            for step in job.get("steps", [])
            if isinstance(step, dict)
        )

    def test_workflow_has_expected_staged_job_set_and_triggers(self) -> None:
        self.assertEqual(set(self.jobs), self.JOBS)
        triggers = self.workflow["on"]
        self.assertIn("pull_request", triggers)
        self.assertIn("workflow_dispatch", triggers)
        self.assertIn("schedule", triggers)
        self.assertEqual(
            triggers["workflow_dispatch"]["inputs"]["force-cache-miss"]["type"],
            "boolean",
        )
        self.assertNotIn("cache-vm-bundles", self.jobs)
        self.assertNotIn("test-nonroot", self.jobs)
        self.assertNotIn("dependency-audit", self.jobs)
        self.assertNotIn("zap-fuzz", self.jobs)
        self.assertNotIn("installed-command-fuzz", self.jobs)

    def test_prebuild_runs_all_sections_before_one_aggregate_failure(self) -> None:
        prebuild = self.jobs["prebuild"]
        steps = {step.get("id"): step for step in prebuild["steps"] if isinstance(step, dict)}
        section_ids = {"contracts", "static", "unit", "security", "cockpit", "nonroot"}
        self.assertTrue(section_ids <= set(steps))
        for section_id in section_ids:
            self.assertEqual(steps[section_id].get("continue-on-error"), "true")

        final = prebuild["steps"][-1]
        self.assertEqual(final.get("if"), "always()")
        final_run = str(final.get("run", ""))
        self.assertIn("scripts/ci-check-report.py", final_run)
        for section_id in section_ids:
            self.assertIn(f"steps.{section_id}.outcome", final_run)

    def test_prebuild_keeps_readable_subcheck_groups_and_annotations(self) -> None:
        text = self.run_text(self.jobs["prebuild"])
        self.assertIn("::group::", text)
        self.assertIn("::error title=", text)
        self.assertIn("GitHub Actions lint", text)
        self.assertIn("Fast Python unit tests", text)
        self.assertIn("Deterministic security regression suite", text)
        self.assertIn("Fresh npm vulnerability audit", text)
        self.assertIn("/home/nas-ci/worktree", self.serialized(self.jobs["prebuild"]))

    def test_coverage_baseline_runs_even_after_other_prebuild_failures(self) -> None:
        coverage = self.jobs["coverage-diff"]
        self.assertEqual(self.needs(coverage), {"prebuild"})
        self.assertIn("always()", str(coverage.get("if", "")))
        self.assertIn("actions/download-artifact", self.serialized(coverage))
        self.assertIn("main-coverage.json", self.serialized(coverage))
        self.assertIn("ci-check-report.py", self.run_text(coverage))

    def test_prepare_is_the_single_expensive_product_producer(self) -> None:
        prepare = self.jobs["prepare"]
        self.assertEqual(self.needs(prepare), {"prebuild", "coverage-diff"})
        text = self.serialized(prepare)
        self.assertIn("Build and verify production Cockpit once", text)
        self.assertIn("cockpit-bundle", text)
        self.assertIn("./.github/actions/prepare-vm-handoff", text)
        self.assertIn("source-archive-evidence", text)
        self.assertIn("force-cache-miss", text)

    def test_handoff_action_keeps_granular_cross_run_caches_but_publishes_one_artifact(self) -> None:
        text = self.serialized(self.handoff)
        self.assertEqual(self.handoff["runs"]["using"], "composite")
        for bundle in self.BUNDLES:
            self.assertIn(f"vm-bundle-{bundle}-", text)
        self.assertEqual(text.count("actions/cache/restore@"), len(self.BUNDLES))
        self.assertEqual(text.count("actions/cache/save@"), len(self.BUNDLES))
        self.assertEqual(text.count("actions/upload-artifact@"), 1)
        self.assertIn("save-missing", text)
        self.assertIn("verify-handoff", text)
        self.assertIn("vm-bundle-handoff", text)
        self.assertIn("nixosConfigurations.nas-ci-ready.config.system.build.toplevel", text)
        self.assertIn("nixosConfigurations.nas-qemu.config.system.build.toplevel", text)

    def test_vm_consumers_download_one_complete_handoff_instead_of_restoring_bundle_caches(self) -> None:
        for name in ("integration", "installer", "installed-security"):
            text = self.serialized(self.jobs[name])
            self.assertIn("vm-bundle-handoff", text)
            self.assertIn("verify-handoff", text)
            self.assertIn("vm-bundles.sh import", text)
            self.assertNotIn("actions/cache/restore@", text)
            self.assertNotIn("vm-bundle-core-", text)

    def test_browser_executes_whole_suite_in_one_runner(self) -> None:
        browser = self.jobs["browser"]
        self.assertNotIn("strategy", browser)
        text = self.serialized(browser)
        self.assertIn("Run complete deterministic browser suite", text)
        self.assertIn("npm --prefix cockpit run test:browser", text)
        self.assertNotIn("NAS_BROWSER_GREP", text)

    def test_integration_keeps_only_the_two_useful_parallel_vm_legs(self) -> None:
        integration = self.jobs["integration"]
        self.assertEqual(integration["strategy"]["fail-fast"], "false")
        legs = integration["strategy"]["matrix"]["include"]
        self.assertEqual({leg["vm"] for leg in legs}, {"unencrypted", "encrypted"})
        self.assertEqual({leg["check"] for leg in legs}, {"nas-vm", "nas-vm-encrypted"})
        self.assertEqual(self.needs(integration), {"prepare"})

    def test_source_fuzz_uses_existing_internal_parallel_runner_not_a_job_matrix(self) -> None:
        fuzz = self.jobs["source-fuzz"]
        self.assertNotIn("strategy", fuzz)
        text = self.run_text(fuzz)
        self.assertIn("scripts/run-fuzz.py --jobs 6", text)
        self.assertIn("source-fuzz.log", text)

    def test_installed_security_provisions_once_and_aggregates_both_workloads(self) -> None:
        job = self.jobs["installed-security"]
        text = self.serialized(job)
        self.assertEqual(text.count("./scripts/qemu-test.sh installer"), 1)
        self.assertIn("installed-command-fuzz", text)
        self.assertIn("zap-fuzz", text)
        self.assertIn("continue-on-error", text)
        self.assertIn("ci-check-report.py", text)

    def test_downstream_dependencies_preserve_stage_order(self) -> None:
        self.assertEqual(self.needs(self.jobs["browser"]), {"prepare"})
        self.assertEqual(self.needs(self.jobs["integration"]), {"prepare"})
        self.assertEqual(self.needs(self.jobs["installer"]), {"prepare", "browser", "integration"})
        self.assertEqual(self.needs(self.jobs["source-fuzz"]), {"integration", "browser", "installer"})
        self.assertEqual(self.needs(self.jobs["installed-security"]), {"installer", "prepare"})
        self.assertEqual(
            self.needs(self.jobs["summary"]),
            self.JOBS - {"summary"},
        )

    def test_github_hosted_job_timeouts_stay_within_platform_limit(self) -> None:
        for name, job in self.jobs.items():
            timeout = int(job.get("timeout-minutes", "360"))
            self.assertLessEqual(timeout, 360, name)
        for name in ("integration", "installer", "installed-security"):
            self.assertEqual(int(self.jobs[name]["timeout-minutes"]), 355)

    def test_actionlint_covers_both_workflows_before_build(self) -> None:
        text = self.run_text(self.jobs["prebuild"])
        self.assertIn("actionlint .github/workflows/ci.yml .github/workflows/release.yml", text)


if __name__ == "__main__":
    unittest.main()
