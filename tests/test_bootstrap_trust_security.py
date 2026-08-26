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
        administrator = source[source.index('bootstrapAdministrator ='):source.index('bootstrapSecrets =')]
        self.assertIn("passwd --lock nas-bootstrap", administrator)
        self.assertIn("/bin/nologin", administrator)
        self.assertIn("--groups wheel", administrator)
        self.assertNotIn("nas-administrators", administrator)
        self.assertNotIn("nas-operations", administrator)
        self.assertNotIn("nixos-nas-bootstrap", source)
        self.assertIn("nas-bootstrap-administrator.serviceConfig.ExecStart = lib.mkOverride 40", source)

    def test_bootstrap_kdbx_is_disposable_and_separate(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        bootstrap_block = source[source.index('bootstrapSecrets ='):source.index('runtimeSelector =')]
        self.assertIn('${bootstrapSecretsDir}/NAS.kdbx', source)
        self.assertIn('${bootstrapRuntimeRoot}/kdbx-password', source)
        self.assertIn("keepassxc-cli db-create", bootstrap_block)
        self.assertIn("refusing to overwrite it", bootstrap_block.lower())
        self.assertNotIn("/var/lib/nas-operational", bootstrap_block)
        self.assertNotIn("zfs-dataset-key", bootstrap_block)
        self.assertNotIn("state-bundle-signing-key", bootstrap_block)

    def test_bootstrap_kdbx_contains_only_bootstrap_authentik_material(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        bootstrap_block = source[source.index('bootstrapSecrets ='):source.index('runtimeSelector =')]
        for name in (
            "authentik-secret-key",
            "authentik-bootstrap-token",
            "authentik-bootstrap-password",
        ):
            self.assertIn(f"ensure_entry {name}", bootstrap_block)
        self.assertNotIn("authentik-api-token", bootstrap_block)
        self.assertNotIn("llama-swap-api-key", bootstrap_block)
        self.assertNotIn("vaultwarden-oidc-client-secret", bootstrap_block)

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

    def test_runtime_switch_never_deletes_populated_authority_directories(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        runtime = source[source.index('runtimeSelector ='):]
        self.assertIn("Refusing to replace non-empty authority directory", runtime)
        self.assertIn("Refusing symlinked identity runtime directory", runtime)
        self.assertIn("rmdir --", runtime)
        self.assertNotIn('rm -rf -- "/var/lib/$name"', runtime)

    def test_original_fixed_linux_password_is_overridden_not_relied_on(self) -> None:
        source = SYSTEMD.read_text(encoding="utf-8")
        self.assertIn("nas-bootstrap-administrator", source)
        hardened = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("lib.mkOverride 40 bootstrapAdministrator", hardened)


if __name__ == "__main__":
    unittest.main()