"""First-run setup wizard contracts - Nix packaging, Caddy routing, and repo wiring."""

import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIZARD = ROOT / "setup/first-run-wizard"
WIZARD_DIST_ASSETS = ("index.html", "first-run-wizard.js", "first-run-wizard.css")


class TestWizardPackaging(unittest.TestCase):
    """The firstRunWizardStatic derivation must package the committed bundle."""

    def setUp(self):
        self.derivation = (ROOT / "modules/nas/internal/documentation-tools.nix").read_text(encoding="utf-8")

    def test_derivation_verifies_every_reviewed_asset(self):
        self.assertIn("for asset in index.html first-run-wizard.js first-run-wizard.css", self.derivation)
        self.assertIn('"$wizard_dist/$asset"', self.derivation)

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


if __name__ == "__main__":
    unittest.main()
