from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class Alpha20CockpitContracts(unittest.TestCase):
    def test_first_start_is_enabled_and_ordered_before_cockpit(self) -> None:
        options = text("modules/nas/options/core.nix")
        services = text("modules/nas/config/systemd-services.nix")
        self.assertIn("firstStart = {", options)
        self.assertIn("default = true;", options.split("firstStart = {", 1)[1].split("};", 1)[0])
        block = services.split("nas-first-start =", 1)[1].split("nas-zfs-unlock =", 1)[0]
        self.assertIn('wantedBy = [ "multi-user.target" ];', block)
        self.assertIn('before = [ "cockpit.socket" ];', block)
        self.assertIn("prepare-first-start", block)

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
        self.assertIn("run npm ci, then npm run build", packaging)
        self.assertIn("cockpit/build.js --check-source", preflight)
        self.assertIn("cockpit/build.js --check", preflight)
        self.assertIn("NAS_PREFLIGHT_SKIP_COCKPIT_BUNDLE", preflight)
        self.assertNotIn("unsafe-inline", text("cockpit/src/manifest.json"))

    def test_release_archive_excludes_node_modules_but_keeps_distribution(self) -> None:
        package = text("scripts/package-release.sh")
        ignored_line = next(line for line in package.splitlines() if line.startswith("ignored_parts ="))
        self.assertIn('"node_modules"', ignored_line)
        self.assertNotIn('"dist"', ignored_line)
        self.assertIn("archive file set does not exactly match staged release", package)

    def test_password_transport_and_destructive_confirmation_remain_explicit(self) -> None:
        api = text("cockpit/src/api.js")
        app = text("cockpit/src/app.jsx")
        self.assertIn("process.input", api)
        self.assertIn('["nas-secrets", "activate-stdin"]', api)
        self.assertIn("allowDestructiveStorage", api)
        self.assertIn("Confirm maintenance action", app)
        self.assertIn("first-start-destructive", app)

    def test_locked_boot_uses_supported_lock_and_trusted_tls(self) -> None:
        live = text("scripts/live-validation.sh")
        locked = live.split("locked_boot()", 1)[1].split("copyparty()", 1)[0]
        self.assertIn("nas-secrets stop", locked)
        self.assertIn('--cacert "$NAS_COCKPIT_CA_FILE"', live)
        self.assertNotIn("--insecure", live)

    def test_syncthing_reconcile_uses_a_durable_generation_journal(self) -> None:
        identity = text("services/nas_identity_sync.py")
        self.assertIn("SYNCTHING_JOURNAL_PATH", identity)
        self.assertIn('"phase": "prepared"', identity)
        self.assertIn("verify_syncthing_configuration", identity)
        self.assertIn('"schemaVersion": 2', identity)

    def test_ci_uses_direct_dependencies_static_build_runtime_final_then_fuzz(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        self.assertLess(workflow.index("Source-only repository preflight"), workflow.index("--coverage coverage.json"))
        self.assertIn('tags: ["v*"]', workflow)
        for retired_gate in ("prebuild-gate:", "build-gate:", "runtime-gate:", "final-system-gate:"):
            self.assertNotIn(retired_gate, workflow)
        self.assertIn("Build qualified Cockpit, source archive, and NixOS closures", workflow)
        self.assertNotIn("  cockpit-build:\n", workflow)
        self.assertNotIn("  source-archive:\n", workflow)
        self.assertIn("Post-build full-stack QEMU integration", workflow)
        self.assertIn("Official-ISO install, reboot, and final-VM deterministic checks", workflow)
        self.assertIn("Final smart fuzz shard (${{ matrix.shard }})", workflow)
        self.assertNotIn("Final hostile-input browser fuzz", workflow)
        self.assertIn("Final installed-command and HTTP adversarial checks", workflow)
        self.assertIn(
            "needs: [test, test-nonroot, security, caddy-validate, static, dependency-audit, coverage-diff]", workflow
        )
        browser_block = workflow.split("  browser:\n", 1)[1].split("  integration:\n", 1)[0]
        integration_block = workflow.split("  integration:\n", 1)[1].split("  installer:\n", 1)[0]
        self.assertIn("needs: [build, test]", browser_block)
        self.assertIn("needs: [build]", integration_block)
        self.assertIn("needs: [integration, browser, build]", workflow)
        self.assertIn("needs: [integration, browser, installer]", workflow)

        build_pos = workflow.index("  build:\n")
        build_block = workflow.split("  build:\n", 1)[1].split("  browser:\n", 1)[0]
        integration_pos = workflow.index("integration:")
        installer_pos = workflow.index("installer:")
        fuzz_pos = workflow.index("  source-fuzz:\n")
        self.assertLess(
            build_block.index("Build production bundle"),
            build_block.index("Package and verify as an untrusted consumer"),
        )
        self.assertLess(
            build_block.index("Package and verify as an untrusted consumer"),
            build_block.index("Build missing testable systems"),
        )
        self.assertLess(build_pos, integration_pos)
        self.assertLess(integration_pos, installer_pos)
        self.assertLess(installer_pos, fuzz_pos)

    def test_ci_parallelizes_independent_qemu_qualifications(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        integration = workflow.split("  integration:\n", 1)[1].split("  installer:\n", 1)[0]
        self.assertIn("name: Post-build full-stack QEMU integration (${{ matrix.vm }})", integration)
        self.assertIn("needs: [build]", integration)
        self.assertIn("fail-fast: false", integration)
        self.assertIn("max-parallel: 2", integration)
        self.assertIn("vm: unencrypted", integration)
        self.assertIn("check: nas-vm", integration)
        self.assertIn("vm: encrypted", integration)
        self.assertIn("check: nas-vm-encrypted", integration)
        self.assertIn('nix build ".#checks.x86_64-linux.${{ matrix.check }}" --show-trace -L', integration)
        self.assertNotIn("Run unencrypted NixOS VM integration tests", integration)
        self.assertNotIn("Run encrypted NixOS VM integration tests", integration)

    def test_release_ci_runs_official_installer_and_final_vm_security(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        final_vm = text("scripts/qemu-final-browser.sh")
        self.assertIn("qemu-test.sh installer", workflow)
        self.assertIn("qemu-final-browser.sh", workflow)
        self.assertIn("zap-automation-scan.sh", final_vm)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("name: cockpit-bundle", workflow)
        self.assertGreaterEqual(workflow.count("npm --prefix cockpit ci --no-audit --no-fund"), 1)
        self.assertNotIn("npm --prefix cockpit install", workflow)
        self.assertIn("npm --prefix cockpit audit --audit-level=high", workflow)
        self.assertIn("Final VM deterministic layout/accessibility/security checks", workflow)
        self.assertIn("Retain active ZAP evidence", workflow)
        self.assertIn("check: nas-vm", workflow)
        self.assertIn("check: nas-vm-encrypted", workflow)

    def test_fast_ci_excludes_generated_fuzz_and_slow_ci_parallelizes_it(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        preflight = text("scripts/preflight.sh")
        security_runner = text("scripts/run-security-tests.py")
        self.assertGreaterEqual(workflow.count("--exclude test_fuzz_boundaries.py"), 3)
        self.assertGreaterEqual(workflow.count("--exclude test_property_invariants.py"), 3)
        self.assertGreaterEqual(workflow.count("--exclude test_secret_security_fuzz.py"), 3)
        self.assertIn("--exclude test_secret_security_fuzz.py", preflight)
        self.assertNotIn("tests.test_secret_security_fuzz", security_runner)
        self.assertIn("max-parallel: 6", workflow)
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("shard: [boundaries, properties, stateful, security, javascript, executable-contracts]", workflow)
        self.assertIn("timeout-minutes: 240", workflow)
        self.assertIn("test-tier == 'full'", workflow)
        self.assertIn("test-tier == 'installer'", workflow)
        fuzz_block = workflow.split("  source-fuzz:\n", 1)[1].split("  installed-command-fuzz:\n", 1)[0]
        self.assertIn("needs: [integration, browser, installer]", fuzz_block)
        self.assertIn("needs.browser.result == 'success'", fuzz_block)
        self.assertIn("github.event_name == 'schedule'", fuzz_block)
        self.assertNotIn("github.event_name == 'pull_request'", fuzz_block)
        self.assertIn("source-fuzz-${{ matrix.shard }}-evidence", fuzz_block)
        self.assertIn('./scripts/run-fuzz.py --suite "${{ matrix.shard }}" --jobs 1', fuzz_block)
        self.assertNotIn("browser-fuzz:", workflow)

        deterministic_installer = workflow.split("  installer:\n", 1)[1].split("  source-fuzz:\n", 1)[0]
        self.assertNotIn("adversarial-installed.py", deterministic_installer)
        self.assertNotIn("NAS_ZAP_IMAGE", deterministic_installer)
        self.assertNotIn("NAS_FINAL_VM_FUZZ", deterministic_installer)

        installed = workflow.split("  installed-command-fuzz:\n", 1)[1].split("  zap-fuzz:\n", 1)[0]
        zap = workflow.split("  zap-fuzz:\n", 1)[1].split("  summary:\n", 1)[0]
        self.assertIn("needs: [installer]", installed)
        self.assertIn("needs: [installer]", zap)
        self.assertIn("qemu-test.sh installer", installed)
        self.assertIn("qemu-test.sh installer", zap)
        self.assertIn("NAS_FINAL_VM_WORKLOAD: installed-command-fuzz", installed)
        self.assertIn("NAS_HTTP_ADVERSARIAL_OUT: http-adversarial.json", installed)
        self.assertIn("http-adversarial.json", installed)
        self.assertIn("NAS_FINAL_VM_WORKLOAD: zap-fuzz", zap)

    def test_cache_policy_distinguishes_dependencies_outputs_results_and_fresh_checks(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        policy = text(".github/CI_CACHE_POLICY.md")
        self.assertIn("CI_CACHE_SCHEMA", workflow)
        self.assertIn("actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae", workflow)
        self.assertIn("v5.0.5", workflow)
        for cache_id in ("fast-result", "caddy-result", "security-result", "source-archive-result", "system-build"):
            self.assertNotIn(f"id: {cache_id}", workflow)
        self.assertNotIn(".ci-cache/", workflow)
        self.assertIn("Query the current npm vulnerability database", workflow)
        self.assertNotIn("~/.cache/nixos-nas-qemu\n", workflow)
        self.assertIn("~/.cache/nixos-nas-qemu/*.iso", workflow)
        self.assertIn("prepare-coverage-baseline.py .", workflow)
        self.assertIn("hashFiles('scripts/prepare-coverage-baseline.py')", workflow)
        coverage_block = workflow.split("  coverage-diff:\n", 1)[1].split("  build:\n", 1)[0]
        self.assertNotIn("magic-nix-cache-action", coverage_block)
        for phrase in (
            "Dependency caches",
            "Cockpit distribution cache",
            "Main coverage baseline data",
            "Immutable installer media",
            "Nix outputs",
            "Qualification results are never pass-cached",
        ):
            self.assertIn(phrase, policy)

    def test_http_adversarial_checks_use_curl_inside_installed_vm_workload(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        config = text("cockpit/e2e/playwright.config.mjs")
        harness = text("scripts/qemu-final-browser.sh")
        installed = workflow.split("  installed-command-fuzz:\n", 1)[1].split("  zap-fuzz:\n", 1)[0]
        http_block = harness.split("run_http_adversarial_contracts()", 1)[1].split('case "$WORKLOAD"', 1)[0]
        self.assertIn("NAS_HTTP_ADVERSARIAL_OUT: http-adversarial.json", installed)
        self.assertIn("run_http_adversarial_contracts", harness)
        self.assertIn("curl --insecure --silent --show-error", http_block)
        self.assertIn("spoofed identity headers reached protected path", http_block)
        self.assertNotIn("NAS_BROWSER_SUITE: fuzz", workflow)
        self.assertNotIn('suite === "fuzz"', config)
        self.assertFalse((ROOT / "cockpit/e2e/ui-fuzz.spec.mjs").exists())
        self.assertFalse((ROOT / "cockpit/e2e/http-adversarial.spec.mjs").exists())

    def test_browser_security_keeps_browser_engines_for_browser_semantics(self) -> None:
        config = text("cockpit/e2e/playwright.config.mjs")
        deterministic = text("cockpit/e2e/common-xss.spec.mjs")
        security = text("cockpit/e2e/ui-security.spec.mjs")
        vm = text("cockpit/e2e/final-vm.spec.mjs")
        harness = text("scripts/qemu-final-browser.sh")
        zap = text("scripts/zap-automation-scan.sh")
        self.assertIn('suite === "vm"', config)
        self.assertNotIn('suite === "fuzz"', config)
        self.assertIn("fullyParallel: true", config)
        self.assertIn("process.env.CI ? 4", config)
        self.assertIn('name: "chromium-final-vm"', config)
        self.assertIn('name: "firefox-final-vm"', config)
        self.assertIn('name: "webkit-final-vm"', config)
        self.assertIn('name: "chromium-mobile-final-vm"', config)
        for probe in ("script-tag", "img-onerror", "svg-onload", "javascript-url", "iframe-srcdoc"):
            self.assertIn(probe, deterministic)
        self.assertIn("hostile status corpus never creates executable elements", security)
        self.assertIn("anonymous clients see only the Cockpit login boundary", vm)
        self.assertIn("anonymous login boundary remains accessible and responsive", vm)
        self.assertIn("invalid credentials cannot expose the NAS component", vm)
        self.assertIn("unexpected interactive element overlaps", vm)
        self.assertIn("confirmation dialog stays usable at extreme zoom and restores focus", vm)
        self.assertIn("#login-user-input", vm)
        self.assertIn("NAS_VM_TEST_PASSWORD", vm)
        self.assertIn("browser-os-overlay.qcow2", harness)
        self.assertIn("deterministic-browser", harness)
        self.assertIn("playwright test", harness)
        self.assertIn("chpasswd", harness)
        self.assertIn("zap-automation-scan.sh", harness)
        self.assertIn('"type": "spiderClient"', zap)
        self.assertIn('"method": "browser"', zap)
        self.assertIn('"type": "activeScan"', zap)


if __name__ == "__main__":
    unittest.main()
