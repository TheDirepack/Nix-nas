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

    def test_release_ci_runs_the_official_iso_installer_path(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        self.assertIn('tags: ["v*"]', workflow)
        self.assertIn("Official-ISO install, final-VM browser, adversarial scan, and reboot", workflow)
        self.assertIn("qemu-test.sh installer", workflow)
        self.assertIn("qemu-final-browser.sh", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("name: cockpit-bundle", workflow)
        self.assertGreaterEqual(workflow.count("npm --prefix cockpit ci --no-audit --no-fund"), 1)
        self.assertNotIn("npm --prefix cockpit install", workflow)
        self.assertIn("npm --prefix cockpit audit --audit-level=high", workflow)
        self.assertIn("Final deterministic browser security gate, then slow fuzz", workflow)
        self.assertIn("Deterministic common XSS, injection, layout, and accessibility probes", workflow)
        self.assertIn("Slow hostile-input browser fuzz after deterministic probes", workflow)
        self.assertIn("Full-stack QEMU integration", workflow)
        self.assertIn("checks.x86_64-linux.nas-vm", workflow)
        self.assertIn("Retain dynamic web-security reports", workflow)

    def test_fast_ci_excludes_fuzz_and_slow_ci_parallelizes_it(self) -> None:
        workflow = text(".github/workflows/ci.yml")
        self.assertGreaterEqual(workflow.count("--exclude test_fuzz_boundaries.py"), 3)
        self.assertGreaterEqual(workflow.count("--exclude test_property_invariants.py"), 3)
        self.assertIn("Slow fuzz/property shard (${{ matrix.shard }})", workflow)
        self.assertIn("shard: [parser-boundaries, executables, properties]", workflow)
        self.assertIn("max-parallel: 3", workflow)
        self.assertIn("test-tier == 'full'", workflow)
        self.assertIn("test-tier == 'installer'", workflow)

    def test_browser_security_has_deterministic_corpus_fuzz_and_final_vm_modes(self) -> None:
        config = text("cockpit/e2e/playwright.config.mjs")
        deterministic = text("cockpit/e2e/common-xss.spec.mjs")
        fuzz = text("cockpit/e2e/ui-fuzz.spec.mjs")
        vm = text("cockpit/e2e/final-vm.spec.mjs")
        harness = text("scripts/qemu-final-browser.sh")
        self.assertIn('suite === "fuzz"', config)
        self.assertIn('suite === "vm"', config)
        self.assertIn("fullyParallel: true", config)
        self.assertIn("workers: process.env.CI ? 4", config)
        for probe in ("script-tag", "img-onerror", "svg-onload", "javascript-url", "iframe-srcdoc"):
            self.assertIn(probe, deterministic)
        self.assertIn("Array.from({length: 96}", fuzz)
        self.assertIn("#login-user-input", vm)
        self.assertIn("NAS_VM_TEST_PASSWORD", vm)
        self.assertIn("browser-os-overlay.qcow2", harness)
        self.assertIn("chpasswd", harness)


if __name__ == "__main__":
    unittest.main()
