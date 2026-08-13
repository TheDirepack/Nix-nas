from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class Alpha20CockpitContracts(unittest.TestCase):
    def test_first_start_is_enabled_and_cockpit_has_qualified_early_boot_ordering(self) -> None:
        options = text("modules/nas/options/core.nix")
        services = text("modules/nas/config/systemd-services.nix")
        system = text("modules/nas/config/system.nix")
        self.assertIn("firstStart = {", options)
        self.assertIn("default = true;", options.split("firstStart = {", 1)[1].split("};", 1)[0])
        first_start = services.split("nas-first-start =", 1)[1].split("nas-zfs-unlock =", 1)[0]
        self.assertIn('wantedBy = [ "multi-user.target" ];', first_start)
        self.assertIn("prepare-first-start", first_start)
        self.assertIn('wantedBy = lib.mkOverride 90 [ "multi-user.target" ]', system)
        self.assertIn("DefaultDependencies = false", system)
        self.assertIn('after = [ "sysinit.target" "basic.target" ]', system)

    def test_cockpit_is_react_patternfly_and_has_no_legacy_dom_renderer(self) -> None:
        package = text("cockpit/package.json")
        index = text("cockpit/src/index.jsx")
        app = text("cockpit/src/app.jsx")
        self.assertIn('"react": "18.3.1"', package)
        self.assertIn('"@patternfly/react-core": "6.1.0"', package)
        self.assertIn("createRoot", index)
        self.assertIn("@patternfly/patternfly/patternfly.css", index)
        self.assertIn('from "@patternfly/react-core"', app)
        for legacy in ("innerHTML", "document.querySelector", "window.confirm"):
            self.assertNotIn(legacy, app)
        for retired in ("nas-render.js", "nas-format.js", "nas.js"):
            self.assertFalse((ROOT / "cockpit/src" / retired).exists())

    def test_starter_kit_build_and_nix_packaging_require_a_complete_bundle(self) -> None:
        build = text("cockpit/build.js")
        packaging = text("modules/nas/internal/documentation-tools.nix")
        preflight = text("scripts/preflight.sh")
        self.assertIn('import("esbuild")', build)
        self.assertIn('import("esbuild-sass-plugin")', build)
        self.assertIn("sourceSha256", build)
        for asset in ("manifest.json", "index.html", "index.js", "index.css", "build-meta.json"):
            self.assertIn(asset, packaging)
        self.assertIn("cockpit/build.js --check-source", preflight)
        self.assertIn("cockpit/build.js --check", preflight)
        self.assertNotIn("unsafe-inline", text("cockpit/src/manifest.json"))

    def test_password_transport_and_destructive_confirmation_remain_explicit(self) -> None:
        api = text("cockpit/src/api.js")
        app = text("cockpit/src/app.jsx")
        self.assertIn("process.input", api)
        self.assertIn('["nas-secrets", "activate-stdin"]', api)
        self.assertIn("allowDestructiveStorage", api)
        self.assertIn("Confirm maintenance action", app)
        self.assertIn("first-start-destructive", app)

    def test_syncthing_reconcile_uses_a_durable_generation_journal(self) -> None:
        identity = text("services/nas_identity_sync.py")
        self.assertIn("SYNCTHING_JOURNAL_PATH", identity)
        self.assertIn('"phase": "prepared"', identity)
        self.assertIn("verify_syncthing_configuration", identity)
        self.assertIn('"schemaVersion": 2', identity)

    def test_ci_uses_direct_fast_dependencies_then_qualified_builds(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        self.assertLess(workflow.index("Source-only repository preflight"), workflow.index("--coverage coverage.json"))
        self.assertIn("Build qualified Cockpit, source archive, and NixOS closures", workflow)
        self.assertIn("Post-build full-stack QEMU integration", workflow)
        self.assertIn("Pipeline summary", workflow)
        for retired_gate in ("prebuild-gate:", "build-gate:", "runtime-gate:", "final-system-gate:"):
            self.assertNotIn(retired_gate, workflow)
        self.assertIn(
            "needs: [test, test-nonroot, security, caddy-validate, static, dependency-audit, coverage-diff]",
            workflow,
        )
        self.assertIn("needs: [build, browser]", workflow)
        self.assertIn("needs: [integration, installer]", workflow)

    def test_release_ci_runs_installer_final_vm_and_security_checks(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        final_vm = text("scripts/qemu-final-browser.sh")
        self.assertIn("qemu-test.sh installer", workflow)
        self.assertIn("qemu-final-browser.sh", workflow)
        self.assertIn("zap-automation-scan.sh", final_vm)
        self.assertIn("npm --prefix cockpit audit --audit-level=high", workflow)
        self.assertIn("checks.x86_64-linux.nas-vm", workflow)

    def test_fast_ci_excludes_slow_property_fuzz_and_parallelizes_it_later(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        preflight = text("scripts/preflight.sh")
        security_runner = text("scripts/run-security-tests.py")
        for name in ("test_fuzz_boundaries.py", "test_property_invariants.py", "test_secret_security_fuzz.py"):
            self.assertIn(f"--exclude {name}", workflow)
        self.assertIn("--exclude test_secret_security_fuzz.py", preflight)
        self.assertNotIn("tests.test_secret_security_fuzz", security_runner)
        self.assertIn("max-parallel: 6", workflow)
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("shard: [boundaries, properties, stateful, security, javascript, executable-contracts]", workflow)
        self.assertIn("timeout-minutes: 240", workflow)

    def test_cache_policy_keeps_dependency_and_vm_reuse_without_pass_caching(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        policy = text(".github/CI_CACHE_POLICY.md")
        self.assertIn("CI_CACHE_SCHEMA", workflow)
        self.assertIn("actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae", workflow)
        self.assertIn("vm-bundles.sh", workflow)
        self.assertNotIn(".ci-cache/", workflow)
        self.assertIn("Qualification results are never pass-cached", policy)

    def test_http_adversarial_checks_use_curl_inside_installed_vm_workload(self) -> None:
        config = text("cockpit/e2e/playwright.config.mjs")
        harness = text("scripts/qemu-final-browser.sh")
        http_block = harness.split("run_http_adversarial_contracts()", 1)[1].split('case "$WORKLOAD"', 1)[0]
        self.assertIn("run_http_adversarial_contracts", harness)
        self.assertIn("curl --insecure --silent --show-error", http_block)
        self.assertIn("spoofed identity headers reached protected path", http_block)
        self.assertNotIn('suite === "fuzz"', config)
        self.assertFalse((ROOT / "cockpit/e2e/ui-fuzz.spec.mjs").exists())

    def test_browser_security_keeps_real_browser_engines_for_browser_semantics(self) -> None:
        config = text("cockpit/e2e/playwright.config.mjs")
        deterministic = text("cockpit/e2e/common-xss.spec.mjs")
        security = text("cockpit/e2e/ui-security.spec.mjs")
        vm = text("cockpit/e2e/final-vm.spec.mjs")
        self.assertIn('name: "chromium-final-vm"', config)
        self.assertIn('name: "firefox-final-vm"', config)
        self.assertIn('name: "webkit-final-vm"', config)
        for probe in ("script-tag", "img-onerror", "svg-onload", "javascript-url", "iframe-srcdoc"):
            self.assertIn(probe, deterministic)
        self.assertIn("hostile status corpus never creates executable elements", security)
        self.assertIn("anonymous clients see only the Cockpit login boundary", vm)
        self.assertIn("unexpected interactive element overlaps", vm)


if __name__ == "__main__":
    unittest.main()
