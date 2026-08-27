from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
APPLICATIONS = ROOT / "modules/nas/config/application-services.nix"
BOOTSTRAP = ROOT / "modules/nas/config/bootstrap-security.nix"


class SetupRuntimeOwnershipTests(unittest.TestCase):
    def test_bootstrap_secret_directory_does_not_require_fixed_admin_user(self) -> None:
        source = APPLICATIONS.read_text(encoding="utf-8")
        self.assertIn('"d ${bootstrapSecretsDir} 0700 root root -"', source)
        self.assertNotIn('"d ${bootstrapSecretsDir} 0700 admin users -"', source)

    def test_permanent_secret_directory_uses_administrator_group_not_fixed_user(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('ensure_runtime_dir "$target/nas-secrets" 0770 root nas-administrators', source)
        self.assertNotIn('ensure_runtime_dir "$target/nas-secrets" 0700 admin users', source)

    def test_application_module_no_longer_contains_parallel_bootstrap_secret_generator(self) -> None:
        source = APPLICATIONS.read_text(encoding="utf-8")
        self.assertNotIn("AUTHENTIK_BOOTSTRAP_PASSWORD=nas-admin-first-boot", source)
        self.assertNotIn('writeShellScript "nas-bootstrap-authentik-secrets"', source)
        hardened = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("nas-bootstrap-kdbx-secrets", hardened)
        self.assertIn("authentik-bootstrap-password", hardened)


if __name__ == "__main__":
    unittest.main()
