"""First-run setup packaging contracts - the served asset must be git-tracked."""

from __future__ import annotations

import unittest

from repo_test_utils import ROOT, text


class FirstRunWizardPackagingTests(unittest.TestCase):
    def test_bootstrap_setup_package_uses_tracked_react_bundle(self) -> None:
        tools = text("modules/nas/internal/documentation-tools.nix")
        wizard_dist = ROOT / "setup/first-run-wizard/dist"

        self.assertTrue(wizard_dist.is_dir(), "the built wizard bundle must be committed")
        for asset in ("index.html", "first-run-wizard.js", "first-run-wizard.css"):
            self.assertTrue(
                (wizard_dist / asset).is_file(),
                f"setup/first-run-wizard/dist/{asset} must be tracked",
            )
        self.assertIn("setup/first-run-wizard/dist", tools)
        self.assertIn("firstRunWizardStatic", tools)
        self.assertIn("first-run-wizard.js", tools)
        self.assertIn("first-run-wizard.css", tools)
        self.assertNotIn("lib/web/portal-static/setup.html", tools)


if __name__ == "__main__":
    unittest.main()
