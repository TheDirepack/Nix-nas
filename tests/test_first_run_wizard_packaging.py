from __future__ import annotations

import unittest

from repo_test_utils import ROOT, text


class FirstRunWizardPackagingTests(unittest.TestCase):
    def test_bootstrap_setup_package_uses_tracked_react_bundle(self) -> None:
        tools = text("modules/nas/internal/documentation-tools.nix")
        wizard_dist = ROOT / "setup/first-run-wizard/dist"

        self.assertTrue((wizard_dist / "index.html").is_file())
        self.assertTrue((wizard_dist / "first-run-wizard.js").is_file())
        self.assertTrue((wizard_dist / "first-run-wizard.css").is_file())
        self.assertIn("setup/first-run-wizard/dist", tools)
        self.assertIn("firstRunWizardStatic", tools)
        self.assertIn("first-run-wizard.js", tools)
        self.assertIn("first-run-wizard.css", tools)
        self.assertNotIn("lib/web/portal-static/setup.html", tools)


if __name__ == "__main__":
    unittest.main()
