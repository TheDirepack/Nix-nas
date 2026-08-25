from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PASSWORD_MODULE = ROOT / "modules/nas/config/password-security.nix"
AUTHENTIK = ROOT / "authentik/blueprints/nas-user-settings.yaml"
API = ROOT / "services/nas_first_run_api.py"
DEFAULT = ROOT / "modules/nas/default.nix"


class PasswordSecurityTests(unittest.TestCase):
    def test_password_security_module_is_imported(self) -> None:
        self.assertIn("./config/password-security.nix", DEFAULT.read_text(encoding="utf-8"))

    def test_setup_uses_mature_strength_and_breach_libraries(self) -> None:
        source = PASSWORD_MODULE.read_text(encoding="utf-8")
        self.assertIn("pythonPackages.zxcvbn", source)
        self.assertIn('pname = "pwnedpasswords"', source)
        self.assertIn('version = "3.1.0"', source)
        self.assertIn("pwnedpasswords.check(password, plain_text=True, timeout=3.0)", source)
        self.assertIn("zxcvbn(password, user_inputs=context)", source)
        self.assertIn("MINIMUM_LENGTH = 15", source)
        self.assertIn("MINIMUM_ZXCVBN_SCORE = 3", source)
        self.assertIn('breach_status = "unavailable"', source)

    def test_setup_api_rejects_breached_but_allows_hibp_unavailable(self) -> None:
        source = API.read_text(encoding="utf-8")
        self.assertIn('result.get("localAccepted") is not True', source)
        self.assertIn('result.get("breachStatus") == "breached"', source)
        self.assertIn('result.get("breachStatus") == "unavailable"', source)
        self.assertNotIn("pwscore", source)

    def test_linux_future_password_changes_use_libpwquality(self) -> None:
        source = PASSWORD_MODULE.read_text(encoding="utf-8")
        self.assertIn("security.pam.services.passwd.rules.password.pwquality", source)
        self.assertIn("pam_pwquality.so", source)
        self.assertIn("minlen = 15", source)
        self.assertIn("dictcheck = 1", source)
        self.assertIn("usercheck = 1", source)
        self.assertIn("enforce_for_root = true", source)

    def test_authentik_native_password_change_policy_is_hardened(self) -> None:
        source = AUTHENTIK.read_text(encoding="utf-8")
        self.assertIn("authentik_policies_password.passwordpolicy", source)
        self.assertIn("default-password-change-password-policy", source)
        self.assertIn("check_have_i_been_pwned: true", source)
        self.assertIn("hibp_allowed_count: 0", source)
        self.assertIn("check_zxcvbn: true", source)
        self.assertIn("zxcvbn_score_threshold: 3", source)
        self.assertIn("length_min: 15", source)


if __name__ == "__main__":
    unittest.main()
