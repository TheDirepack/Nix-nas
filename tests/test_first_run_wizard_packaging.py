from __future__ import annotations

import unittest

from repo_test_utils import ROOT, text


class FirstRunWizardPackagingTests(unittest.TestCase):
    def test_bootstrap_setup_package_uses_tracked_static_source(self) -> None:
        tools = text("modules/nas/internal/documentation-tools.nix")
        static_setup = ROOT / "lib/web/portal-static/setup.html"

        self.assertTrue(static_setup.is_file())
        self.assertIn("lib/web/portal-static/setup.html", tools)
        self.assertNotIn("setup/first-run-wizard/dist", tools)
        self.assertNotIn("first-run-wizard.js", tools)
        self.assertNotIn("first-run-wizard.css", tools)


if __name__ == "__main__":
    unittest.main()
