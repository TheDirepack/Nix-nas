"""First-run setup wizard contracts - Nix packaging, Caddy routing, and repo wiring."""

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIZARD = ROOT / "setup/first-run-wizard"
WIZARD_DIST_ASSETS = ("index.html", "first-run-wizard.js", "first-run-wizard.css", "build-meta.json")


class TestWizardPackaging(unittest.TestCase):
    """The firstRunWizardStatic derivation must package the committed bundle."""

    def setUp(self):
        self.derivation = (ROOT / "modules/nas/internal/documentation-tools.nix").read_text(encoding="utf-8")

    def test_derivation_verifies_every_reviewed_asset(self):
        self.assertIn(
            "for asset in index.html first-run-wizard.js first-run-wizard.css build-meta.json",
            self.derivation,
        )
        self.assertIn('"$wizard_dist/$asset"', self.derivation)

    def test_derivation_rejects_stale_or_tampered_output(self):
        self.assertIn("build.js --check", self.derivation)

    def test_derivation_installs_the_full_bundle_tree(self):
        self.assertIn('install -d "$out/share/nas-portal-wizard"', self.derivation)
        self.assertIn('cp -R "$wizard_dist/." "$out/share/nas-portal-wizard/"', self.derivation)

    def test_derivation_is_exported_through_nas_internal(self):
        self.assertIn("firstRunWizardStatic", self.derivation.split("in", 1)[-1])

    def test_committed_bundle_contains_the_verified_assets(self):
        for asset in WIZARD_DIST_ASSETS:
            path = WIZARD / "dist" / asset
            self.assertTrue(path.exists(), f"dist/{asset} must be committed")
            self.assertGreater(path.stat().st_size, 0, f"dist/{asset} must not be empty")
        self.assertTrue((WIZARD / "dist/assets").is_dir(), "dist font assets must be committed")

    def test_reviewed_lockfile_is_committed(self):
        lockfile = WIZARD / "package-lock.json"
        self.assertTrue(lockfile.exists(), "setup/first-run-wizard/package-lock.json must be committed")
        lock = json.loads(lockfile.read_text(encoding="utf-8"))
        packages = lock.get("packages", {})
        self.assertIn("node_modules/@patternfly/react-core", packages)
        self.assertEqual(packages["node_modules/@patternfly/react-core"]["version"], "6.1.0")

    def test_structure_validation_allowlists_the_generated_dist(self):
        validator = (ROOT / "scripts/validate-structure.py").read_text(encoding="utf-8")
        self.assertIn('ROOT / "setup" / "first-run-wizard" / "dist"', validator)


class TestWizardRouting(unittest.TestCase):
    """Caddy must serve the wizard from the store behind forward-auth."""

    def setUp(self):
        self.bootstrap = (ROOT / "modules/nas/config/caddy-bootstrap.nix").read_text(encoding="utf-8")

    def test_bootstrap_imports_the_wizard_derivation(self):
        self.assertIn("firstRunWizardStatic", self.bootstrap)

    def test_setup_route_serves_the_wizard_store_path(self):
        start = self.bootstrap.index("handle /setup/* {")
        end = self.bootstrap.find("\n  }\n", start)
        route = self.bootstrap[start:end]
        self.assertIn("uri strip_prefix /setup", route)
        self.assertIn("root * ${firstRunWizardStatic}/share/nas-portal-wizard", route)
        self.assertIn("file_server", route)

    def test_detached_job_capabilities_survive_authentik_regeneration(self):
        status = self.bootstrap.index("handle /setup/api/first-start/job {")
        reboot = self.bootstrap.index("handle /setup/api/reboot {")
        gated = self.bootstrap.index("handle /setup/api/* {")
        self.assertLess(status, gated)
        self.assertLess(reboot, gated)
        self.assertNotIn("caddyForwardAuth", self.bootstrap[status:reboot])
        self.assertIn("caddyForwardAuth", self.bootstrap[gated : gated + 180])
        self.assertNotIn("handle /setup/api/first-start/job/*", self.bootstrap)

    def test_setup_api_reaches_only_the_permissioned_socket(self):
        self.assertNotIn("8980", self.bootstrap)
        self.assertNotIn("127.0.0.1:8980", self.bootstrap)
        self.assertEqual(self.bootstrap.count("reverse_proxy unix//run/nas-setup-api/setup.sock"), 3)

    def test_wizard_assets_are_served_under_the_setup_prefix(self):
        # Relative asset URLs in index.html resolve to /setup/first-run-wizard.*;
        # the stripped-prefix file server must be the only handler needed.
        index_html = (WIZARD / "index.html").read_text(encoding="utf-8")
        self.assertIn('src="./first-run-wizard.js"', index_html)
        self.assertIn('href="./first-run-wizard.css"', index_html)


class TestWizardSource(unittest.TestCase):
    """Source-level constraints that keep the bundle buildable and honest."""

    def test_package_pins_the_cockpit_patternfly_generation(self):
        wizard_pkg = json.loads((WIZARD / "package.json").read_text(encoding="utf-8"))
        cockpit_pkg = json.loads((ROOT / "cockpit/package.json").read_text(encoding="utf-8"))
        for dep in ("@patternfly/patternfly", "@patternfly/react-core", "react", "react-dom"):
            self.assertEqual(
                wizard_pkg["dependencies"][dep],
                cockpit_pkg["dependencies"][dep],
                f"{dep} must match the cockpit plugin generation",
            )

    def test_entry_point_uses_the_react_core_61_wizard_children_api(self):
        index = (WIZARD / "src/index.jsx").read_text(encoding="utf-8")
        self.assertNotIn("steps={[", index, "react-core 6.1.0 ignores the steps-array prop")
        self.assertIn("<WizardStep", index)
        self.assertIn("@patternfly/patternfly/patternfly.css", index)

    def test_no_runtime_secret_material_in_the_wizard_tree(self):
        # The wizard is a public-static bundle behind forward-auth; it must not
        # embed credentials or generated secrets.
        for source in (WIZARD / "src").rglob("*.js*"):
            text = source.read_text(encoding="utf-8")
            self.assertNotIn("nas-admin-first-boot", text, f"{source.name} embeds bootstrap credentials")

    def test_capability_never_touches_urls_storage_or_logs(self):
        sources = {path: path.read_text(encoding="utf-8") for path in (WIZARD / "src").rglob("*.js*")}
        combined = "\n".join(sources.values())
        self.assertNotIn("api/first-start/job/", combined)
        self.assertNotIn("localStorage", sources[WIZARD / "src/steps/ConfirmStep.jsx"])
        self.assertNotIn("sessionStorage", combined)
        self.assertIn("X-NAS-Setup-Capability", combined)
        self.assertIn("api/first-start/resume", combined)
        self.assertIn("wizard-job-document", combined)

    def test_refresh_resumes_without_resubmitting(self):
        confirm = (WIZARD / "src/steps/ConfirmStep.jsx").read_text(encoding="utf-8")
        self.assertIn("api/first-start/resume", confirm)
        effect = confirm.split("if (job || resumeAttempted) return undefined;")[1].split(
            "}, [job, resumeAttempted, resume]);"
        )[0]
        self.assertNotIn("submit(", effect)
        self.assertNotIn("api/first-run", effect)

    def test_completion_states_are_distinct_and_reboot_is_gated(self):
        confirm = (WIZARD / "src/steps/ConfirmStep.jsx").read_text(encoding="utf-8")
        self.assertIn('variant="warning"', confirm)
        self.assertIn("Setup completed with unverified state", confirm)
        self.assertIn('variant="success"', confirm)
        self.assertIn("rebootAuthorized", confirm)
        self.assertIn("Request reboot access", confirm)


class TestSetupApiBoundary(unittest.TestCase):
    """The setup backend listens on a Caddy-only Unix socket with bounded requests."""

    def setUp(self):
        self.services = (ROOT / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
        start = self.services.index("systemd.services.nas-setup-api = {")
        end = self.services.index("};", start)
        self.unit = self.services[start:end]
        self.backend = (ROOT / "services/nas_cockpit_api.py").read_text(encoding="utf-8")

    def test_unit_serves_a_permissioned_socket(self):
        self.assertIn("serve --socket-path /run/nas-setup-api/setup.sock", self.unit)
        self.assertNotIn("--bind", self.unit)
        self.assertNotIn("--port", self.unit)
        self.assertNotIn("8980", self.unit)
        self.assertIn('RuntimeDirectory = "nas-setup-api"', self.unit)
        self.assertIn("NAS_CADDY_USER=", self.unit)
        self.assertIn("NAS_CADDY_GROUP=", self.unit)

    def test_unit_admits_only_unix_sockets(self):
        self.assertIn('RestrictAddressFamilies = [ "AF_UNIX" ]', self.unit)
        self.assertNotIn("AF_INET", self.unit)

    def test_backend_has_no_tcp_listener_or_url_capability(self):
        self.assertNotIn("ThreadingHTTPServer", self.backend)
        self.assertNotIn("127.0.0.1:8980", self.backend)
        self.assertNotIn("SETUP_API_JOB_RE", self.backend)
        self.assertIn("SetupApiUnixServer", self.backend)
        self.assertIn("X-NAS-Setup-Capability", self.backend)
        self.assertIn("/setup/api/first-start/resume", self.backend)

    def test_browser_flow_uses_page_state_not_url_capabilities(self):
        script = (ROOT / "tests/browser/first-run-wizard.py").read_text(encoding="utf-8")
        self.assertNotIn("first-start/job/${", script)
        self.assertIn("wizard-job-document", script)


class TestWizardBuildIntegrity(unittest.TestCase):
    """The wizard must carry the same source-bound stale/tampered-output contract as Cockpit."""

    def setUp(self):
        self.helper = ROOT / "scripts" / "frontend-build-integrity.cjs"
        self.build_js = (WIZARD / "build.js").read_text(encoding="utf-8")

    def test_both_frontends_share_one_integrity_helper(self):
        self.assertTrue(self.helper.is_file(), "the shared frontend build-integrity helper must exist")
        self.assertIn("frontend-build-integrity", self.build_js)
        cockpit = (ROOT / "cockpit" / "build.js").read_text(encoding="utf-8")
        self.assertIn("frontend-build-integrity", cockpit)
        self.assertNotIn('createHash("sha256")', self.build_js)

    def test_ci_qualifies_the_wizard_lockfile_and_bundle(self):
        qualification = (ROOT / "scripts" / "ci-qualification.sh").read_text(encoding="utf-8")
        self.assertIn("setup/first-run-wizard", qualification)
        self.assertIn("--prefix setup/first-run-wizard audit", qualification)
        self.assertIn("setup/first-run-wizard/build.js --check", qualification)

    def test_release_verifies_the_wizard_bundle(self):
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("setup/first-run-wizard", release)
        self.assertIn("setup/first-run-wizard/build.js --check", release)

    def stage_tree(self, raw: str) -> pathlib.Path:
        """Copy the wizard tree (reusing installed modules) for destructive probes."""
        staged = pathlib.Path(raw) / "wizard"
        shutil.copytree(WIZARD, staged, ignore=shutil.ignore_patterns("node_modules"))
        modules = WIZARD / "node_modules"
        if modules.is_dir():
            os.symlink(modules, staged / "node_modules")
        return staged

    def run_check(self, staged: pathlib.Path) -> subprocess.CompletedProcess[str]:
        # Staged copies live outside the repository tree, so point them at the
        # reviewed helper through the same override the Nix sandbox uses.
        env = {**os.environ, "NAS_FRONTEND_INTEGRITY_HELPER": str(ROOT / "scripts" / "frontend-build-integrity.cjs")}
        return subprocess.run(
            ["node", "build.js", "--check"],
            cwd=staged,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )

    def dist_hashes(self, staged: pathlib.Path) -> dict[str, str]:
        hashes = {}
        for path in sorted((staged / "dist").rglob("*")):
            if path.is_file() and not os.path.islink(path):
                hashes[str(path.relative_to(staged))] = hashlib.sha256(path.read_bytes()).hexdigest()
        return hashes

    def test_check_mode_rejects_stale_source_without_rewriting(self):
        with tempfile.TemporaryDirectory(prefix="nas-wizard-probe-a-") as raw:
            staged = self.stage_tree(raw)
            before = self.dist_hashes(staged)
            with (staged / "src" / "index.jsx").open("a", encoding="utf-8") as handle:
                handle.write("\n// integrity probe\n")
            result = self.run_check(staged)
            self.assertNotEqual(result.returncode, 0, "--check must fail on stale source")
            self.assertIn("stale", (result.stderr + result.stdout).lower())
            self.assertEqual(before, self.dist_hashes(staged), "--check must never rewrite output")

    def test_check_mode_rejects_tampered_output_without_rewriting(self):
        with tempfile.TemporaryDirectory(prefix="nas-wizard-probe-b-") as raw:
            staged = self.stage_tree(raw)
            bundle = staged / "dist" / "first-run-wizard.js"
            with bundle.open("ab") as handle:
                handle.write(b"\n/* integrity probe */\n")
            tampered = self.dist_hashes(staged)
            result = self.run_check(staged)
            self.assertNotEqual(result.returncode, 0, "--check must fail on tampered output")
            output = result.stderr + result.stdout
            self.assertTrue(
                "match" in output.lower() or "stale" in output.lower(),
                f"--check must report a metadata mismatch: {output[:500]}",
            )
            self.assertEqual(tampered, self.dist_hashes(staged), "--check must never rewrite output")

    def test_check_mode_rejects_missing_metadata(self):
        with tempfile.TemporaryDirectory(prefix="nas-wizard-probe-c-") as raw:
            staged = self.stage_tree(raw)
            (staged / "dist" / "build-meta.json").unlink()
            result = self.run_check(staged)
            self.assertNotEqual(result.returncode, 0, "--check must fail on missing build metadata")

    def test_clean_build_restores_check_success(self):
        modules = WIZARD / "node_modules"
        if not (modules / "esbuild").exists():
            self.skipTest("wizard build dependencies are not installed")
        with tempfile.TemporaryDirectory(prefix="nas-wizard-probe-d-") as raw:
            staged = self.stage_tree(raw)
            with (staged / "src" / "index.jsx").open("a", encoding="utf-8") as handle:
                handle.write("\n// integrity probe\n")
            stale = self.run_check(staged)
            self.assertNotEqual(stale.returncode, 0, "stale source must fail before rebuild")
            built = subprocess.run(
                ["node", "build.js"],
                cwd=staged,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=300,
                env={
                    **os.environ,
                    "NODE_ENV": "production",
                    "NAS_FRONTEND_INTEGRITY_HELPER": str(ROOT / "scripts" / "frontend-build-integrity.cjs"),
                },
            )
            self.assertEqual(built.returncode, 0, f"clean rebuild must succeed: {built.stderr[-2000:]}")
            restored = self.run_check(staged)
            self.assertEqual(restored.returncode, 0, f"--check must pass after rebuild: {restored.stderr[-2000:]}")


if __name__ == "__main__":
    unittest.main()
