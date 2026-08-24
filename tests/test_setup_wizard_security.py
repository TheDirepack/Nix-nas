from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIZARD = ROOT / "setup" / "first-run-wizard" / "src"


class SetupWizardSecurityTests(unittest.TestCase):
    def test_first_run_schema_requires_independent_human_credentials(self) -> None:
        schema = json.loads((WIZARD / "forms" / "schema.json").read_text(encoding="utf-8"))
        properties = schema["properties"]
        required = set(schema["required"])

        self.assertIsNone(properties["adminUsername"].get("default"))
        self.assertNotIn("useSamePassword", properties)
        self.assertNotIn("createOutpost", properties)
        self.assertNotIn("createProviderApp", properties)
        self.assertLessEqual(
            {
                "adminPassword",
                "adminPasswordConfirm",
                "keePassMasterPassword",
                "keePassMasterPasswordConfirm",
                "authentikAdministratorPassword",
                "authentikAdministratorPasswordConfirm",
            },
            required,
        )
        for field in (
            "adminPassword",
            "adminPasswordConfirm",
            "keePassMasterPassword",
            "keePassMasterPasswordConfirm",
            "authentikAdministratorPassword",
            "authentikAdministratorPasswordConfirm",
        ):
            self.assertGreaterEqual(properties[field]["minLength"], 15)

    def test_wizard_does_not_offer_fixed_admin_or_shared_keepass_password(self) -> None:
        admin_source = (WIZARD / "steps" / "AdminStep.jsx").read_text(encoding="utf-8")

        self.assertNotIn("useSamePassword", admin_source)
        self.assertNotIn("Use the same password", admin_source)
        self.assertNotIn("useState('admin')", admin_source)
        self.assertIn("Choose a new local username", admin_source)
        self.assertIn("KeePassXC master password", admin_source)

    def test_browser_api_never_generates_secret_bearing_nix_or_logs_credentials(self) -> None:
        api_source = (WIZARD / "api.js").read_text(encoding="utf-8")

        self.assertNotIn("writeTempNixConfig", api_source)
        self.assertNotIn("users.users.admin", api_source)
        self.assertNotIn("console.log", api_source)
        self.assertNotIn("fs.write", api_source)
        self.assertIn("redirect: 'error'", api_source)
        self.assertIn("credentials: 'same-origin'", api_source)
        self.assertIn("cache: 'no-store'", api_source)

    def test_authentik_setup_uses_separate_human_password_and_managed_static_objects(self) -> None:
        source = (WIZARD / "steps" / "AuthentikStep.jsx").read_text(encoding="utf-8")

        self.assertIn("Authentik administrator password", source)
        self.assertIn("Confirm Authentik administrator password", source)
        self.assertNotIn("createOutpost", source)
        self.assertNotIn("createProviderApp", source)
        self.assertIn("embedded proxy outpost", source)


if __name__ == "__main__":
    unittest.main()
