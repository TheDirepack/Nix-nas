from __future__ import annotations

import json
import math
import pathlib
import unittest
from typing import Any

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
TIMEOUT_MANIFEST = ROOT / "tests" / "vm" / "timeout-budget.json"


class CiWorkflowGraphTests(unittest.TestCase):
    BUNDLES = ("core", "identity", "observability", "storage", "ai", "vm-drivers")

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        cls.jobs = cls.workflow["jobs"]
        cls.timeout_manifest = json.loads(TIMEOUT_MANIFEST.read_text(encoding="utf-8"))

    @staticmethod
    def needs(job: dict[str, Any]) -> set[str]:
        value = job.get("needs", [])
        if isinstance(value, list):
            return {str(item) for item in value}
        return {str(value)}

    @staticmethod
    def run_text(job: dict[str, Any]) -> str:
        return "\n".join(str(step.get("run", "")) for step in job.get("steps", []) if isinstance(step, dict))

    @staticmethod
    def serialized(job: dict[str, Any]) -> str:
        return repr(job)

    def test_workflow_has_a_scheduled_qualification_trigger(self) -> None:
        triggers = self.workflow["on"]
        self.assertIn("pull_request", triggers)
        self.assertIn("workflow_dispatch", triggers)
        self.assertIn("schedule", triggers)
        self.assertEqual(self.workflow["on"]["workflow_dispatch"]["inputs"]["force-cache-miss"]["type"], "boolean")

    def test_vm_matrix_runs_both_legs_without_fail_fast(self) -> None:
        integration = self.jobs["integration"]
        self.assertEqual(integration["strategy"]["fail-fast"], "false")
        legs = integration["strategy"]["matrix"]["include"]
        self.assertEqual({leg["vm"] for leg in legs}, {"unencrypted", "encrypted"})
        self.assertEqual({leg["check"] for leg in legs}, {"nas-vm", "nas-vm-encrypted"})

    def test_qualification_dependencies_are_explicit_and_complete(self) -> None:
        self.assertEqual(self.needs(self.jobs["browser"]), {"build"})
        self.assertEqual(self.needs(self.jobs["integration"]), {"build"})
        self.assertEqual(self.needs(self.jobs["cache-vm-bundles"]), {"build"})
        self.assertTrue({"build", "browser", "integration"} <= self.needs(self.jobs["installer"]))
        self.assertTrue({"integration", "browser", "installer"} <= self.needs(self.jobs["source-fuzz"]))
        self.assertEqual(self.needs(self.jobs["installed-command-fuzz"]), {"installer"})
        self.assertEqual(self.needs(self.jobs["zap-fuzz"]), {"installer"})

    def test_destructive_jobs_are_not_on_pull_requests_and_are_scheduled(self) -> None:
        for name in ("browser", "integration", "source-fuzz"):
            condition = str(self.jobs[name].get("if", ""))
            self.assertNotIn("pull_request", condition)
            self.assertIn("schedule", condition)

    def test_summary_depends_on_every_release_critical_job_including_cache(self) -> None:
        summary_needs = self.needs(self.jobs["summary"])
        expected = {
            "test",
            "test-nonroot",
            "security",
            "caddy-validate",
            "static",
            "dependency-audit",
            "coverage-diff",
            "build",
            "cache-vm-bundles",
            "browser",
            "integration",
            "installer",
            "source-fuzz",
            "installed-command-fuzz",
            "zap-fuzz",
        }
        self.assertEqual(summary_needs, expected)

    def test_handoff_is_verified_by_each_consumer_and_checksum_is_published(self) -> None:
        build_text = self.serialized(self.jobs["build"])
        self.assertIn("bundle_cache_complete", build_text)
        self.assertIn("Determine whether the exact VM bundle set was restored", build_text)
        self.assertIn("Export missing Nix store bundles for downstream VMs", build_text)
        self.assertIn("steps.vm_bundle_handoff.outputs.cache_complete != 'true'", build_text)
        self.assertIn("bundle-manifest.tsv", build_text)
        self.assertIn("bundle-handoff.sha256", build_text)
        self.assertIn("Restore verified source archive", build_text)
        self.assertIn("source-archive-${{ github.sha }}", build_text)
        for name in ("integration", "cache-vm-bundles"):
            text = self.serialized(self.jobs[name])
            if name == "integration":
                self.assertIn("bundle_cache_complete == 'true'", text)
                self.assertIn("vm-bundle-handoff", text)
                self.assertIn("verify-handoff", text)
            else:
                self.assertIn("actions/checkout", text)
                self.assertIn("needs.build.outputs.bundle_cache_complete != 'true'", text)
                self.assertIn("vm-bundle-handoff", text)
                self.assertIn("verify-handoff", text)
        self.assertIn(
            "Report cache persistence status",
            "\n".join(str(step.get("name", "")) for step in self.jobs["cache-vm-bundles"]["steps"]),
        )

    def test_forced_cache_miss_uses_an_isolated_namespace_and_runs_persistence(self) -> None:
        build = self.serialized(self.jobs["build"])
        cache = self.serialized(self.jobs["cache-vm-bundles"])
        self.assertIn("force-cache-miss", build)
        self.assertIn("-forced-%s", build)
        self.assertIn("bundle_cache_namespace", build)
        self.assertIn("needs.build.outputs.bundle_cache_namespace", cache)
        self.assertIn("bundle_cache_complete != 'true'", cache)

    def test_ci_timeouts_equal_manifest_aggregates(self) -> None:
        manifest = self.timeout_manifest
        timeouts = manifest["timeouts"]
        outer = manifest["outer"]
        guest = (
            sum(
                phase["fixedSeconds"]
                + phase["ordinaryWaits"] * manifest["ordinaryWaitSeconds"]
                + sum(timeouts[key] for key in phase["timeoutKeys"])
                for phase in manifest["phases"]
            )
            + manifest["slackSeconds"]
        )
        integration = (
            guest
            + timeouts["secretAdversarial"]
            + timeouts["installedSmoke"]
            + outer["nativeBoot"]
            + outer["nativeShutdown"]
            + outer["slack"]
        )
        installer = (
            guest
            + timeouts["reconfigure"]
            + outer["installerSetup"]
            + outer["installerBoot"]
            + outer["installerReboot"]
            + outer["nativeShutdown"]
            + outer["slack"]
        )
        self.assertEqual(int(self.jobs["integration"]["timeout-minutes"]), math.ceil(integration / 60))
        self.assertEqual(int(self.jobs["installer"]["timeout-minutes"]), math.ceil(installer / 60))

    def test_every_bundle_has_one_exact_cache_key_through_the_handoff(self) -> None:
        build = self.serialized(self.jobs["build"])
        cache = self.serialized(self.jobs["cache-vm-bundles"])
        integration = self.serialized(self.jobs["integration"])
        for name in self.BUNDLES:
            step_id = name.replace("-", "_")
            self.assertIn(f"key_{step_id}", build)
            self.assertIn(f"vm_bundle_{step_id}", build)
            self.assertIn(f"vm-bundle-{name}-", build)
            self.assertIn(f"vm-bundle-{name}-", cache)
            self.assertIn(f"vm-bundle-{name}-", integration)

    def test_optional_skipped_dependencies_do_not_suppress_downstream_tiers(self) -> None:
        for name in ("cache-vm-bundles", "browser", "integration", "installer"):
            condition = str(self.jobs[name].get("if", ""))
            self.assertIn("always()", condition)
        installer_condition = str(self.jobs["installer"].get("if", ""))
        self.assertIn("needs.browser.result == 'success'", installer_condition)
        self.assertIn("needs.integration.result == 'success'", installer_condition)
        self.assertIn("github.event.inputs.test-tier == 'full'", installer_condition)

    def test_actionlint_is_a_static_job_gate(self) -> None:
        static_run = self.run_text(self.jobs["static"])
        self.assertIn("actionlint", static_run)


if __name__ == "__main__":
    unittest.main()
