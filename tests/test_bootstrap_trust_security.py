from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "modules/nas/config/bootstrap-security.nix"
SYSTEMD = ROOT / "modules/nas/config/systemd-services.nix"
APPLICATIONS = ROOT / "modules/nas/config/application-services.nix"
DEFAULT = ROOT / "modules/nas/default.nix"


class BootstrapTrustSecurityTests(unittest.TestCase):
    def test_security_module_is_imported(self) -> None:
        self.assertIn("./config/bootstrap-security.nix", DEFAULT.read_text(encoding="utf-8"))

    def test_linux_bootstrap_account_has_no_password_login(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("passwd --lock nas-bootstrap", source)
        self.assertIn("/bin/nologin", source)
        self.assertNotIn("nixos-nas-bootstrap", source)
        self.assertIn("nas-bootstrap-administrator.serviceConfig.ExecStart = lib.mkForce", source)

    def test_bootstrap_kdbx_is_disposable_and_separate(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('${bootstrapSecretsDir}/NAS.kdbx', source)
        self.assertIn('${bootstrapRuntimeRoot}/kdbx-password', source)
        self.assertIn("keepassxc-cli db-create", source)
        self.assertIn("refusing to overwrite it", source.lower())
        self.assertNotIn("/var/lib/nas-operational", source)
        self.assertNotIn("zfs-dataset-key", source)
        self.assertNotIn("state-bundle-signing-key", source)

    def test_bootstrap_kdbx_contains_only_bootstrap_authentik_material(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        for name in (
            "authentik-secret-key",
            "authentik-bootstrap-token",
            "authentik-bootstrap-password",
        ):
            self.assertIn(f"ensure_entry {name}", source)
        self.assertNotIn("authentik-api-token", source)
        self.assertNotIn("llama-swap-api-key", source)
        self.assertNotIn("vaultwarden-oidc-client-secret", source)

    def test_bootstrap_human_password_is_installation_unique_and_console_only(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertNotIn("nas-admin-first-boot", source)
        self.assertIn('ensure_entry authentik-bootstrap-password "$(${pkgs.openssl}/bin/openssl rand -hex 16)"', source)
        self.assertIn('> /dev/console', source)
        self.assertNotIn('echo "$bootstrap_password"', source)
        self.assertNotIn('printf \'%s\\n\' "$bootstrap_password"', source)

    def test_bootstrap_secrets_are_not_promoted(self) -> None:
        apps = APPLICATIONS.read_text(encoding="utf-8")
        self.assertNotIn('cp -a "$target', apps)
        self.assertNotIn('mv "$source', apps)
        self.assertIn("Nothing is", apps)
        self.assertIn("copied from bootstrap", apps)

    def test_original_fixed_linux_password_is_overridden_not_relied_on(self) -> None:
        source = SYSTEMD.read_text(encoding="utf-8")
        # Until the large service module is simplified, keep this regression
        # visible: bootstrap-security.nix must remain the effective override.
        self.assertIn("nas-bootstrap-administrator", source)
        hardened = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("lib.mkForce bootstrapAdministrator", hardened)


if __name__ == "__main__":
    unittest.main()
