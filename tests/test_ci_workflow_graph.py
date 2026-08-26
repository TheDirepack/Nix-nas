from __future__ import annotations

import pathlib
import unittest
from typing import Any

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
HANDOFF_ACTION = ROOT / ".github" / "actions" / "prepare-vm-handoff" / "action.yml"
NIX_SETUP_ACTION = ROOT / ".github" / "actions" / "setup-nix-ci" / "action.yml"
CHECK_HELPER = ROOT / ".github" / "ci-checks.sh"
QUALIFICATION_SCRIPT = ROOT / "scripts" / "ci-qualification.sh"


class CiWorkflowGraphTests(unittest.TestCase):
    BUNDLES = ("core", "identity", "observability", "storage", "ai", "vm-drivers")
    PARALLEL = {"static", "unit", "security", "nonroot", "cockpit"}
    JOBS = {
        "prerequisites",
        *PARALLEL,
        "coverage-diff",
        "qualification",
        "prepare",
        "browser",
        "integration",
        "installer",
        "source-fuzz",
        "installed-security",
        "summary",
        "maintenance",
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.load(
            WORKFLOW.read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        cls.jobs = cls.workflow["jobs"]
        cls.handoff = yaml.load(
            HANDOFF_ACTION.read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        cls.nix_setup = yaml.load(
            NIX_SETUP_ACTION.read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        cls.check_helper = CHECK_HELPER.read_text(encoding="utf-8")
        cls.qualification_script = QUALIFICATION_SCRIPT.read_text(encoding="utf-8")

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
        for retired in (
            "prebuild",
            "cache-vm-bundles",
            "test-nonroot",
            "dependency-audit",
            "zap-fuzz",
            "installed-command-fuzz",
        ):
            self.assertNotIn(retired, self.jobs)

    def test_shared_prerequisites_run_before_parallel_fanout(self) -> None:
        prerequisites = self.jobs["prerequisites"]
        text = self.serialized(prerequisites)
        self.assertIn("./.github/actions/setup-nix-ci", text)
        self.assertIn("nix develop .#test -c true", text)
        self.assertIn("scripts/ci-qualification.sh shared", text)
        self.assertIn("qualification-shared-logs", text)
        for name in self.PARALLEL:
            self.assertEqual(self.needs(self.jobs[name]), {"prerequisites"})

    def test_parallel_branches_have_no_cross_dependencies_and_always_report(self) -> None:
        for name in self.PARALLEL:
            job = self.jobs[name]
            dependencies = self.needs(job)
            self.assertEqual(dependencies, {"prerequisites"}, name)
            self.assertTrue(dependencies.isdisjoint(self.PARALLEL), name)
            self.assertIn("!cancelled()", str(job.get("if", "")), name)

    def test_branch_specific_prerequisites_stay_local(self) -> None:
        cockpit = self.serialized(self.jobs["cockpit"])
        self.assertIn("actions/setup-node@", cockpit)
        self.assertIn("cache-dependency-path", cockpit)
        self.assertIn("npm --prefix cockpit ci", cockpit)
        self.assertNotIn("cockpit/node_modules", cockpit)
        for name in self.PARALLEL - {"cockpit"}:
            text = self.serialized(self.jobs[name])
            self.assertNotIn("cockpit/node_modules", text, name)
            self.assertIn("./.github/actions/setup-nix-ci", text, name)

    def test_each_parallel_branch_keeps_detailed_failure_logs(self) -> None:
        helper = self.check_helper
        self.assertIn("ci_run()", helper)
        self.assertIn("::group::%s", helper)
        self.assertIn("::error title=%s", helper)
        self.assertIn("PIPESTATUS[0]", helper)
        self.assertIn("date +%s", helper)
        self.assertIn("printf -v command_text '%q '", helper)
        for name in self.PARALLEL:
            text = self.serialized(self.jobs[name])
            self.assertIn("ci-check-report.py", text, name)
            self.assertIn(f"qualification-{name}-logs", text, name)
            self.assertIn("--tail-lines 30", text, name)

    def test_qualification_script_preserves_all_subcheck_groups(self) -> None:
        script = self.qualification_script
        for marker in (
            "Source-only repository preflight",
            "GitHub Actions lint",
            "Fast Python unit tests",
            "Deterministic security regression suite",
            "Run the fast suite without root-owned state",
            "Fresh npm vulnerability audit",
            "Production Cockpit bundle",
        ):
            self.assertIn(marker, script)
        self.assertNotIn("nix shell nixpkgs#", script)
        self.assertIn("nix develop .#test -c bats", script)
        self.assertIn("nix develop .#test -c prettier", script)

    def test_coverage_comparison_starts_after_unit_only(self) -> None:
        coverage = self.jobs["coverage-diff"]
        self.assertEqual(self.needs(coverage), {"unit"})
        self.assertIn("!cancelled()", str(coverage.get("if", "")))
        self.assertIn("coverage-report", self.serialized(coverage))
        self.assertIn("main-coverage.json", self.serialized(coverage))
        self.assertIn("ci-check-report.py", self.run_text(coverage))
        self.assertIn("baseline-build", self.serialized(coverage))
        self.assertNotIn("main-coverage-cache=", self.run_text(coverage))

    def test_qualification_gate_joins_all_parallel_checks_once(self) -> None:
        gate = self.jobs["qualification"]
        expected = {"prerequisites", *self.PARALLEL, "coverage-diff"}
        self.assertEqual(self.needs(gate), expected)
        self.assertIn("!cancelled()", str(gate.get("if", "")))
        text = self.run_text(gate)
        for name in expected:
            self.assertIn(f"needs.{name}.result", text)

    def test_cockpit_builds_once_and_prepare_consumes_the_artifact(self) -> None:
        cockpit = self.serialized(self.jobs["cockpit"])
        prepare = self.serialized(self.jobs["prepare"])
        self.assertIn("Production Cockpit bundle", self.qualification_script)
        self.assertIn("cockpit-bundle", cockpit)
        self.assertIn("Restore reviewed Cockpit bundle", prepare)
        self.assertIn("cockpit-bundle", prepare)
        self.assertNotIn("npm --prefix cockpit run build", prepare)
        self.assertNotIn("cockpit/node_modules", prepare)

    def test_prepare_is_the_single_expensive_nix_product_producer(self) -> None:
        prepare = self.jobs["prepare"]
        self.assertEqual(self.needs(prepare), {"qualification"})
        text = self.serialized(prepare)
        self.assertIn("./.github/actions/prepare-vm-handoff", text)
        self.assertIn("source-archive-evidence", text)
        self.assertIn("force-cache-miss", text)
        self.assertIn("Package and verify as an untrusted consumer", text)

    def test_nix_setup_action_centralizes_repeated_runner_setup(self) -> None:
        self.assertEqual(self.nix_setup["runs"]["using"], "composite")
        text = self.serialized(self.nix_setup)
        self.assertIn("cachix/install-nix-action@", text)
        self.assertIn("DeterminateSystems/magic-nix-cache-action@", text)
        self.assertIn("enable-kvm", text)

    def test_handoff_action_keeps_granular_cross_run_caches_but_publishes_one_artifact(
        self,
    ) -> None:
        text = self.serialized(self.handoff)
        self.assertEqual(self.handoff["runs"]["using"], "composite")
        for bundle in self.BUNDLES:
            self.assertIn(f"vm-bundle-{bundle}-", text)
        self.assertEqual(text.count("actions/cache/restore@"), len(self.BUNDLES))
        self.assertEqual(text.count("actions/cache/save@"), len(self.BUNDLES))
        self.assertEqual(text.count("actions/upload-artifact@"), 1)
        self.assertIn("save-missing", text)
        self.assertIn("verify-handoff", text)
        self.assertIn("system-handoff.sh save", text)
        self.assertIn("system-handoff.sh verify", text)
        self.assertIn("vm-bundle-handoff", text)
        self.assertIn(
            "nixosConfigurations.nas-ci-ready.config.system.build.toplevel",
            text,
        )
        self.assertIn("nixosConfigurations.nas-qemu.config.system.build.toplevel", text)

    def test_vm_consumers_download_one_complete_handoff_instead_of_restoring_bundle_caches(
        self,
    ) -> None:
        for name in ("integration", "installer", "installed-security"):
            text = self.serialized(self.jobs[name])
            self.assertIn("vm-bundle-handoff", text)
            self.assertIn("verify-handoff", text)
            self.assertIn("vm-bundles.sh import", text)
            self.assertIn("system-handoff.sh verify", text)
            self.assertIn("system-handoff.sh import", text)
            self.assertNotIn("actions/cache/restore@", text)
            self.assertNotIn("vm-bundle-core-", text)

    def test_browser_executes_whole_suite_in_one_runner(self) -> None:
        browser = self.jobs["browser"]
        self.assertNotIn("strategy", browser)
        text = self.serialized(browser)
        self.assertIn("Run complete deterministic browser suite", text)
        self.assertIn("npm --prefix cockpit run test:browser", text)
        self.assertIn("npm --prefix cockpit ci", text)
        self.assertNotIn("cockpit/node_modules", text)
        self.assertNotIn("NAS_BROWSER_GREP", text)

    def test_integration_keeps_only_the_two_useful_parallel_vm_legs(self) -> None:
        integration = self.jobs["integration"]
        self.assertEqual(integration["strategy"]["fail-fast"], "false")
        legs = integration["strategy"]["matrix"]["include"]
        self.assertEqual({leg["vm"] for leg in legs}, {"unencrypted", "encrypted"})
        self.assertEqual(
            {leg["check"] for leg in legs},
            {"nas-vm", "nas-vm-encrypted"},
        )
        self.assertEqual(self.needs(integration), {"prepare"})

    def test_source_fuzz_uses_existing_internal_parallel_runner_not_a_job_matrix(
        self,
    ) -> None:
        fuzz = self.jobs["source-fuzz"]
        self.assertNotIn("strategy", fuzz)
        text = self.run_text(fuzz)
        self.assertIn("scripts/run-fuzz.py --jobs 6", text)
        self.assertIn("fuzz-evidence/source-fuzz.log", text)
        self.assertNotIn(".fuzz-evidence", text)

    def test_failure_evidence_avoids_hidden_paths(self) -> None:
        installer = self.serialized(self.jobs["installer"])
        installed = self.serialized(self.jobs["installed-security"])
        self.assertIn("final-vm-evidence/browser-console.log", installer)
        self.assertIn("installed-security-logs/browser-console.log", installed)
        self.assertNotIn("~/.cache/nixos-nas-qemu/state/browser-console.log'", installer)

    def test_installed_security_provisions_once_and_aggregates_both_workloads(
        self,
    ) -> None:
        job = self.jobs["installed-security"]
        text = self.serialized(job)
        self.assertEqual(text.count("./scripts/qemu-test.sh installer"), 1)
        self.assertIn("installed-command-fuzz", text)
        self.assertIn("zap-fuzz", text)
        self.assertIn("continue-on-error", text)
        self.assertIn("ci-check-report.py", text)

    def test_maintenance_prunes_only_repo_owned_state_without_blocking_ci(self) -> None:
        maintenance = self.jobs["maintenance"]
        self.assertEqual(self.needs(maintenance), {"summary"})
        self.assertIn("!cancelled()", str(maintenance.get("if", "")))
        self.assertIn("github.event_name == 'push'", str(maintenance.get("if", "")))
        self.assertNotIn("pull_request", str(maintenance.get("if", "")))
        self.assertEqual(maintenance["permissions"]["actions"], "write")
        self.assertEqual(maintenance["permissions"]["contents"], "read")
        text = self.serialized(maintenance)
        self.assertIn("continue-on-error", text)
        self.assertIn("/actions/runs?status=completed", text)
        self.assertIn("/actions/caches?per_page=100", text)
        self.assertIn('[[ "$key" == ci-* ]]', text)
        self.assertIn("$CI_CACHE_SCHEMA", text)
        self.assertIn("-forced-", text)
        self.assertIn("-source-archive-", text)
        self.assertIn("CURRENT_RUN_ID", text)
        self.assertIn("active-workflows", text)
        self.assertIn("deleted_runs < 200", text)
        self.assertIn("deleted_caches < 200", text)

    def test_downstream_dependencies_preserve_stage_order(self) -> None:
        self.assertEqual(self.needs(self.jobs["prepare"]), {"qualification"})
        self.assertEqual(self.needs(self.jobs["browser"]), {"prepare"})
        self.assertEqual(self.needs(self.jobs["integration"]), {"prepare"})
        self.assertEqual(
            self.needs(self.jobs["installer"]),
            {"prepare", "browser", "integration"},
        )
        self.assertEqual(
            self.needs(self.jobs["source-fuzz"]),
            {"integration", "browser", "installer"},
        )
        self.assertEqual(
            self.needs(self.jobs["installed-security"]),
            {"installer", "prepare"},
        )
        self.assertEqual(self.needs(self.jobs["summary"]), self.JOBS - {"summary", "maintenance"})
        self.assertEqual(self.needs(self.jobs["maintenance"]), {"summary"})

    def test_github_hosted_job_timeouts_stay_within_platform_limit(self) -> None:
        for name, job in self.jobs.items():
            timeout = int(job.get("timeout-minutes", "360"))
            self.assertLessEqual(timeout, 360, name)
        for name in ("integration", "installer", "installed-security"):
            self.assertEqual(int(self.jobs[name]["timeout-minutes"]), 355)
        self.assertEqual(int(self.jobs["maintenance"]["timeout-minutes"]), 10)

    def test_actionlint_covers_both_workflows_before_build(self) -> None:
        self.assertIn("actionlint", self.qualification_script)
        self.assertIn(".github/workflows/ci.yml", self.qualification_script)
        self.assertIn(".github/workflows/release.yml", self.qualification_script)
        self.assertEqual(
            self.qualification_script.count(
                'unexpected key "queue" for "concurrency" section'
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
