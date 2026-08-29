from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIZARD = ROOT / "setup" / "first-run-wizard" / "src"
STATIC_SCAN = ROOT / "scripts" / "security-static-scan.py"


class SetupWizardSecurityTests(unittest.TestCase):
    def test_first_run_schema_defaults_password_reuse_off_without_fixed_admin(self) -> None:
        source = (WIZARD / "index.jsx").read_text(encoding="utf-8")
        admin = (WIZARD / "steps" / "AdminStep.jsx").read_text(encoding="utf-8")
        self.assertIn("emptyAdministrator = { username: ''", source)
        self.assertIn("useSamePassword", source)
        self.assertIn("minLength={12}", admin)
        self.assertNotIn("username: 'admin'", source)

    def test_wizard_offers_an_explicit_keepass_password_reuse_toggle(self) -> None:
        admin_source = (WIZARD / "steps" / "AdminStep.jsx").read_text(encoding="utf-8")
        index_source = (WIZARD / "index.jsx").read_text(encoding="utf-8")

        self.assertIn("Use the same password for the KeePassXC database", admin_source)
        self.assertIn("useSamePassword", index_source)
        self.assertIn("keePassEffective", index_source)
        self.assertIn("authentikAdministratorPassword={administrator.password}", index_source)
        self.assertNotIn("username: 'admin'", index_source)

    def test_wizard_surfaces_shared_password_strength_and_breach_feedback(self) -> None:
        quality = (WIZARD / "PasswordQuality.jsx").read_text(encoding="utf-8")
        admin = (WIZARD / "steps" / "AdminStep.jsx").read_text(encoding="utf-8")
        api = (WIZARD / "api.js").read_text(encoding="utf-8")

        self.assertIn("passwordQuality(password", quality)
        self.assertIn("zxcvbnScore", quality)
        self.assertIn("breachStatus === 'breached'", quality)
        self.assertIn("breachStatus === 'unavailable'", quality)
        self.assertIn("PasswordQualityFeedback", admin)
        self.assertIn("onBlur", admin)
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
        self.assertIn("setKeePassPasswordConfirm('')", index_source)
        self.assertIn("onSecretsSubmitted={clearSecrets}", index_source)
        self.assertIn("onSecretsSubmitted?.()", confirm_source)
        self.assertIn('Cache-Control "no-store"', caddy)

    def test_privileged_wizard_is_covered_by_static_web_security_scan(self) -> None:
        scanner = STATIC_SCAN.read_text(encoding="utf-8")
        self.assertIn('ROOT / "setup" / "first-run-wizard" / "src"', scanner)

    def test_authentik_setup_uses_managed_static_objects(self) -> None:
        source = (WIZARD / "steps" / "ConfirmStep.jsx").read_text(encoding="utf-8")

        self.assertIn("Authentik administrator password", source)
        self.assertIn("authentikAdministratorPassword", source)
        self.assertNotIn("createOutpost", source)
        self.assertNotIn("createProviderApp", source)


if __name__ == "__main__":
    unittest.main()
