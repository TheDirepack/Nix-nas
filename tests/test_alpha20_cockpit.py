from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def caddy_forward_auth_marker(bootstrap: str) -> str:
    marker = "forward_auth 127.0.0.1:${toString authentikOutpostPort}"
    if marker in bootstrap:
        return marker
    raise AssertionError("outpost forward_auth target missing from bootstrap Caddyfile")


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class Alpha20CockpitContracts(unittest.TestCase):
    def test_first_start_is_enabled(self) -> None:
        options = text("modules/nas/options/core.nix")
        services = text("modules/nas/config/systemd-services.nix")
        self.assertIn("firstStart = {", options)
        self.assertIn(
            "default = true;",
            options.split("firstStart = {", 1)[1].split("};", 1)[0],
        )
        first_start = services.split("nas-first-start =", 1)[1].split("nas-zfs-unlock =", 1)[0]
        self.assertIn('wantedBy = [ "multi-user.target" ];', first_start)
        self.assertIn("prepare-first-start", first_start)

    def test_cockpit_sits_behind_caddy_authentik_gate(self) -> None:
        application = text("modules/nas/config/application-services.nix")
        bootstrap = text("modules/nas/config/caddy-bootstrap.nix")
        system = text("modules/nas/config/system.nix")
        seed = text("modules/nas/config/managed-services-seed-v2.nix")
        self.assertIn("nas-cockpit-sso", application)
        self.assertIn("--local-session", application)
        self.assertIn("cockpit-bridge", application)
        self.assertIn("--no-tls", application)
        cockpit_sso = application.split("nas-cockpit-sso =", 1)[1].split("};", 1)[0]
        self.assertIn('after = [ "nas-first-start.service" ];', cockpit_sso)
        self.assertIn('requires = [ "nas-first-start.service" ];', cockpit_sso)
        self.assertNotIn('partOf = [ "nas-first-start.service" ];', cockpit_sso)
        self.assertNotIn("settings.bearer", application)
        self.assertNotIn("nas-cockpit-oauth", application)
        # Caddy owns authorization: forward auth via the outpost plus the
        # nas_admin group check before any request reaches Cockpit.
        console = bootstrap.split("handle /console* {", 1)[1].split("reverse_proxy", 1)[0]
        self.assertIn("${caddyForwardAuth}", console)
        self.assertIn("missingCockpitAdmin", console)
        self.assertIn("respond @missingCockpitAdmin 403", console)
        self.assertIn("--address 127.0.0.1", application)
        self.assertIn("systemd.sockets.cockpit.enable = false;", system)
        self.assertNotIn("ConditionPathExists = lib.mkOverride", system)
        cockpit = seed.split("cockpit = {", 1)[1].split("    };\n  };", 1)[0]
        self.assertIn('unit = "nas-cockpit-sso.service";', cockpit)
        self.assertIn('mode = "identity";', cockpit)
        self.assertIn('capability = "admin";', cockpit)

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
        operations = text("cockpit/src/pages/operations-page.jsx")
        setup_page = text("cockpit/src/pages/setup-page.jsx")
        self.assertIn("process.input", api)
        self.assertIn('["nas-secrets", "activate-stdin"]', api)
        self.assertIn("allowDestructiveStorage", api)
        self.assertIn("Confirm maintenance action", operations)
        self.assertIn("first-start-destructive", setup_page)

    def test_syncthing_reconcile_uses_a_durable_generation_journal(self) -> None:
        identity = text("services/nas_identity_sync.py")
        self.assertIn("SYNCTHING_JOURNAL_PATH", identity)
        self.assertIn('"phase": "prepared"', identity)
        self.assertIn("verify_syncthing_configuration", identity)
        self.assertIn('"schemaVersion": 2', identity)

    def test_ci_uses_prerequisite_fanout_and_reusable_build_handoffs(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        qualification = text("scripts/ci-qualification.sh")
        handoff = text(".github/actions/prepare-vm-handoff/action.yml")
        self.assertIn("Shared qualification prerequisites", workflow)
        self.assertIn("Realize pinned test toolchain once", workflow)
        self.assertIn("nix develop .#test -c true", workflow)
        for job_name in ("Static analysis and configuration", "Unit, coverage, and maintainer contracts", "Security and generated configuration", "Unprivileged hermeticity", "Cockpit source, dependencies, and production bundle"):
            self.assertIn(job_name, workflow)
        self.assertGreaterEqual(workflow.count("needs: [prerequisites]"), 5)
        self.assertIn("needs: [unit]", workflow)
        self.assertIn("Qualification gate", workflow)
        self.assertIn("needs: [qualification]", workflow)
        self.assertIn("Prepare reusable build handoff", workflow)
        self.assertIn("Full-stack QEMU integration", workflow)
        self.assertIn("Pipeline summary", workflow)
        self.assertIn("ci-check-report.py", workflow)
        self.assertIn("Source-only repository preflight", qualification)
        self.assertIn("--coverage coverage.json", qualification)
        self.assertIn("vm-bundle-handoff", handoff)
        for retired_gate in ("prebuild:", "prebuild-gate:", "build-gate:", "runtime-gate:", "final-system-gate:", "cache-vm-bundles:"):
            self.assertNotIn(retired_gate, workflow)

    def test_release_ci_runs_installer_final_vm_and_security_checks(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        qualification = text("scripts/ci-qualification.sh")
        final_vm = text("scripts/qemu-final-browser.sh")
        self.assertIn("qemu-test.sh installer", workflow)
        self.assertIn("qemu-final-browser.sh", workflow)
        self.assertIn("zap-automation-scan.sh", final_vm)
        self.assertIn("npm --prefix cockpit audit --audit-level=high", qualification)
        self.assertIn("checks.x86_64-linux", workflow)

    def test_fast_ci_excludes_slow_properties_then_uses_internal_fuzz_parallelism(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        qualification = text("scripts/ci-qualification.sh")
        preflight = text("scripts/preflight.sh")
        security_runner = text("scripts/run-security-tests.py")
        fuzz_runner = text("scripts/run-fuzz.py")
        for name in ("test_fuzz_boundaries.py", "test_property_invariants.py", "test_secret_security_fuzz.py"):
            self.assertIn(f"--exclude {name}", qualification)
        self.assertIn("--exclude test_secret_security_fuzz.py", preflight)
        self.assertNotIn("tests.test_secret_security_fuzz", security_runner)
        self.assertIn("scripts/run-fuzz.py --jobs 6", workflow)
        self.assertNotIn("shard:", workflow)
        for shard in ("boundaries", "custom-inputs", "properties", "stateful", "security", "javascript", "executable-contracts"):
            self.assertIn(f'"{shard}"', fuzz_runner)
        self.assertIn("timeout-minutes: 240", workflow)

    def test_cache_policy_keeps_dependency_and_vm_reuse_without_pass_caching(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        handoff = text(".github/actions/prepare-vm-handoff/action.yml")
        policy = text(".github/CI_CACHE_POLICY.md")
        self.assertIn("CI_CACHE_SCHEMA", workflow)
        self.assertIn("actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae", workflow)
        self.assertIn("actions/cache/restore@27d5ce7f107fe9357f9df03efb73ab90386fccae", handoff)
        self.assertIn("actions/cache/save@27d5ce7f107fe9357f9df03efb73ab90386fccae", handoff)
        self.assertIn("vm-bundles.sh", handoff)
        self.assertIn("vm-bundle-handoff", workflow)
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
        server = text("cockpit/e2e/deterministic-server.mjs")
        runtime_stub = text("cockpit/e2e/cockpit-runtime-stub.js")
        deterministic = text("cockpit/e2e/common-xss.spec.mjs")
        security = text("cockpit/e2e/ui-security.spec.mjs")
        vm = text("cockpit/e2e/final-vm.spec.mjs")
        self.assertIn('name: "chromium-final-vm"', config)
        self.assertIn('name: "firefox-final-vm"', config)
        self.assertIn('name: "webkit-final-vm"', config)
        self.assertIn('command: "node e2e/deterministic-server.mjs"', config)
        self.assertIn('"/base1/cockpit.js"', server)
        self.assertIn('name === "cockpit"', runtime_stub)
        for probe in ("script-tag", "img-onerror", "svg-onload", "javascript-url", "iframe-srcdoc"):
            self.assertIn(probe, deterministic)
        self.assertIn("hostile status corpus never creates executable elements", security)
        self.assertIn('frame.locator(".nas-actions button").first()', vm)
        self.assertIn("function firstMaintenanceAction", security)
        self.assertIn("anonymous clients see only the Cockpit login boundary", vm)
        self.assertIn("unexpected interactive element overlaps", vm)


if __name__ == "__main__":
    unittest.main()
