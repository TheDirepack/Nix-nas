from __future__ import annotations

import unittest

from repo_test_utils import text


class NixFrontendBuildTests(unittest.TestCase):
    def test_frontend_sources_exclude_local_dependencies_and_generated_output(self) -> None:
        source = text("modules/nas/internal/documentation-tools.nix")
        self.assertIn("pkgs.lib.cleanSourceWith", source)
        self.assertIn('[ "node_modules" "dist" ]', source)
        self.assertIn("npmRoot = frontendSource;", source)

    def test_one_lockfile_builder_verifies_production_output(self) -> None:
        source = text("modules/nas/internal/documentation-tools.nix")
        self.assertEqual(source.count("pkgs.buildNpmPackage"), 1)
        self.assertIn('NODE_ENV = "production";', source)
        self.assertIn('PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1";', source)
        self.assertIn("node build.js --check", source)
        self.assertIn("builtins.readFile ../../../VERSION", source)
        self.assertIn('mkFrontendBundle "cockpit-nas-bundle" ../../../cockpit', source)
        self.assertIn('mkFrontendBundle "first-run-wizard-bundle" ../../../setup/first-run-wizard', source)
