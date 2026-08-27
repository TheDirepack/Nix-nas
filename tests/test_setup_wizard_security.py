from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIZARD = ROOT / "setup" / "first-run-wizard" / "src"
STATIC_SCAN = ROOT / "scripts" / "security-static-scan.py"


class SetupWizardSecurityTests(unittest.TestCase):
    def test_first_run_schema_defaults_password_reuse_off_without_fixed_admin(self) -> None:
        schema = json.loads((WIZARD / "forms" / "schema.json").read_text(encoding="utf-8"))
        properties = schema["properties"]
        required = set(schema["required"])

        self.assertIsNone(properties["adminUsername"].get("default"))
        self.assertFalse(properties["reuseLinuxPasswordForKeePass"]["default"])
        self.assertFalse(properties["reuseLinuxPasswordForAuthentik"]["default"])
        self.assertNotIn("createOutpost", properties)
        self.assertNotIn("createProviderApp", properties)
        self.assertLessEqual(
            {
                "adminPassword",
                "adminPasswordConfirm",
                "reuseLinuxPasswordForKeePass",
                "reuseLinuxPasswordForAuthentik",
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

    def test_wizard_offers_two_explicit_linux_password_reuse_toggles(self) -> None:
        admin_source = (WIZARD / "steps" / "AdminStep.jsx").read_text(encoding="utf-8")
        authentik_source = (WIZARD / "steps" / "AuthentikStep.jsx").read_text(encoding="utf-8")
        index_source = (WIZARD / "index.jsx").read_text(encoding="utf-8")

        self.assertIn("Reuse the Linux administrator password for KeePassXC", admin_source)
        self.assertIn("Reuse the Linux administrator password for Authentik", authentik_source)
        self.assertIn("reuseLinuxPasswordForKeePass", index_source)
        self.assertIn("reuseLinuxPasswordForAuthentik", index_source)
        self.assertIn("React.useState(false)", index_source)
        self.assertIn("effectiveKeePassPassword", index_source)
        self.assertIn("effectiveAuthentikPassword", index_source)
        self.assertNotIn("username: 'admin'", index_source)
        self.assertIn("Choose a new local username", admin_source)

    def test_wizard_surfaces_shared_password_strength_and_breach_feedback(self) -> None:
        quality = (WIZARD / "PasswordQuality.jsx").read_text(encoding="utf-8")
        admin = (WIZARD / "steps" / "AdminStep.jsx").read_text(encoding="utf-8")
        authentik = (WIZARD / "steps" / "AuthentikStep.jsx").read_text(encoding="utf-8")
        api = (WIZARD / "api.js").read_text(encoding="utf-8")

        self.assertIn("passwordQuality(password", quality)
        self.assertIn("zxcvbnScore", quality)
        self.assertIn("breachStatus === 'breached'", quality)
        self.assertIn("breachStatus === 'unavailable'", quality)
        self.assertIn("PasswordQualityFeedback", admin)
        self.assertIn("PasswordQualityFeedback", authentik)
        self.assertIn("onBlur", admin)
        self.assertIn("onBlur", authentik)
        self.assertIn("api/password-quality", api)

    def test_browser_api_never_generates_secret_bearing_nix_or_logs_credentials(self) -> None:
        api_source = (WIZARD / "api.js").read_text(encoding="utf-8")

        self.assertNotIn("writeTempNixConfig", api_source)
        self.assertNotIn("users.users.admin", api_source)
        self.assertNotIn("console.log", api_source)
        self.assertNotIn("fs.write", api_source)
        self.assertIn("redirect: 'error'", api_source)
        self.assertIn("credentials: 'same-origin'", api_source)
        self.assertIn("cache: 'no-store'", api_source)

    def test_password_state_is_cleared_after_backend_accepts_submission(self) -> None:
        index_source = (WIZARD / "index.jsx").read_text(encoding="utf-8")
        confirm_source = (WIZARD / "steps" / "ConfirmStep.jsx").read_text(encoding="utf-8")
        caddy = (ROOT / "modules/nas/config/caddy-bootstrap.nix").read_text(encoding="utf-8")

        self.assertIn("const clearSecrets = React.useCallback", index_source)
        self.assertIn("password: '', confirm: ''", index_source)
        self.assertIn("setKeePassPassword('')", index_source)
        self.assertIn("setAuthentikAdministratorPassword('')", index_source)
        self.assertIn("onSecretsSubmitted={clearSecrets}", index_source)
        self.assertIn("onSecretsSubmitted?.()", confirm_source)
        self.assertIn('Cache-Control "no-store"', caddy)

    def test_privileged_wizard_is_covered_by_static_web_security_scan(self) -> None:
        scanner = STATIC_SCAN.read_text(encoding="utf-8")
        self.assertIn('ROOT / "setup" / "first-run-wizard" / "src"', scanner)

    def test_authentik_setup_uses_managed_static_objects(self) -> None:
        source = (WIZARD / "steps" / "AuthentikStep.jsx").read_text(encoding="utf-8")

        self.assertIn("Authentik administrator password", source)
        self.assertIn("Confirm Authentik administrator password", source)
        self.assertNotIn("createOutpost", source)
        self.assertNotIn("createProviderApp", source)
        self.assertIn("embedded proxy outpost", source)


if __name__ == "__main__":
    unittest.main()
