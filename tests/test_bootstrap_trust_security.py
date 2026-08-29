from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "modules/nas/config/bootstrap-security.nix"
SYSTEMD = ROOT / "modules/nas/config/systemd-services.nix"
APPLICATIONS = ROOT / "modules/nas/config/application-services.nix"
DEFAULT = ROOT / "modules/nas/default.nix"


class BootstrapTrustSecurityTests(unittest.TestCase):
    def test_security_module_is_imported_once(self) -> None:
        source = DEFAULT.read_text(encoding="utf-8")
        self.assertIn("./config/bootstrap-security.nix", source)
        self.assertNotIn("bootstrap-runtime-credentials.nix", source)
        self.assertNotIn("security-hardening-overrides.nix", source)

    def test_linux_bootstrap_account_has_no_password_login(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        administrator = source[source.index("bootstrapAdministrator =") : source.index("bootstrapSecrets =")]
        self.assertIn("passwd --lock nas-bootstrap", administrator)
        self.assertIn("/bin/nologin", administrator)
        self.assertIn("--groups wheel", administrator)
        self.assertNotIn("nas-administrators", administrator)
        self.assertNotIn("nas-operations", administrator)
        self.assertNotIn("nixos-nas-bootstrap", source)
        self.assertIn("nas-bootstrap-administrator.serviceConfig.ExecStart = lib.mkOverride 40", source)

    def test_bootstrap_kdbx_is_disposable_and_separate(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        bootstrap_block = source[source.index("bootstrapSecrets =") : source.index("runtimeSelector =")]
        self.assertIn("${bootstrapSecretsDir}/NAS.kdbx", source)
        self.assertIn("${bootstrapRuntimeRoot}/kdbx-password", source)
        self.assertIn("keepassxc-cli db-create", bootstrap_block)
        self.assertIn("refusing to overwrite it", bootstrap_block.lower())
        self.assertNotIn("/var/lib/nas-operational", bootstrap_block)
        self.assertNotIn("zfs-dataset-key", bootstrap_block)
        self.assertNotIn("state-bundle-signing-key", bootstrap_block)

    def test_bootstrap_kdbx_contains_only_bootstrap_authentik_material(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        bootstrap_block = source[source.index("bootstrapSecrets =") : source.index("runtimeSelector =")]
        for name in (
            "authentik-secret-key",
            "authentik-bootstrap-token",
            "authentik-bootstrap-password",
        ):
            self.assertIn(f"ensure_entry {name}", bootstrap_block)
        self.assertNotIn("authentik-api-token", bootstrap_block)
        self.assertNotIn("llama-swap-api-key", bootstrap_block)
        self.assertNotIn("vaultwarden-oidc-client-secret", bootstrap_block)

    def test_bootstrap_human_password_is_known_and_disposable(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('bootstrapAuthentikPassword = "nas-admin-first-boot";', source)
        self.assertIn(
            "ensure_entry authentik-bootstrap-password ${lib.escapeShellArg bootstrapAuthentikPassword}", source
        )
        self.assertNotIn(
            'ensure_entry authentik-bootstrap-password "$(${pkgs.openssl}/bin/openssl rand -hex 16)"', source
        )
        self.assertIn('[[ "$bootstrap_password" == ${lib.escapeShellArg bootstrapAuthentikPassword} ]]', source)
        self.assertNotIn("> /dev/console", source)
        self.assertIn("disposable bootstrap Authentik authority", source)

    def test_bootstrap_runtime_credentials_are_private_regular_run_files(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        runtime = source[source.index("runtimeSelector =") :]
        self.assertIn("Bootstrap credential source must be a regular non-symlink file", runtime)
        self.assertIn("install -m 0640 -o root -g authentik", runtime)
        self.assertIn("install -m 0400 -o root -g root", runtime)
        self.assertIn('if [[ "$target" == "$bootstrap_root" ]]', runtime)
        self.assertIn("ln -s", runtime)

    def test_bootstrap_secrets_are_not_promoted(self) -> None:
        apps = APPLICATIONS.read_text(encoding="utf-8")
        self.assertNotIn('cp -a "$target', apps)
        self.assertNotIn('mv "$source', apps)
        self.assertIn("Nothing is", apps)
        self.assertIn("copied from bootstrap", apps)

    def test_runtime_switch_never_deletes_populated_authority_directories(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")
        runtime = source[source.index("runtimeSelector =") :]
        self.assertIn("Refusing to replace non-empty authority directory", runtime)
        self.assertIn("Refusing symlinked identity runtime directory", runtime)
        self.assertIn("rmdir --", runtime)
        self.assertNotIn('rm -rf -- "/var/lib/$name"', runtime)

    def test_bootstrap_units_keep_lifecycle_and_identity_pull_order(self) -> None:
        hardened = BOOTSTRAP.read_text(encoding="utf-8")
        apps = APPLICATIONS.read_text(encoding="utf-8")
        secrets = hardened[hardened.index("systemd.services.nas-bootstrap-authentik-secrets = {") :]
        self.assertIn('description = "Create the first-boot-only Authentik runtime secrets";', secrets)
        self.assertIn('"!/var/lib/nas-setup/operational-runtime-select"', secrets)
        self.assertIn('"!/var/lib/nas-setup/state.json"', secrets)
        self.assertIn('Type = "oneshot";', secrets)
        self.assertIn("RemainAfterExit = true;", secrets)
        self.assertIn('UMask = "0077";', secrets)
        selector = apps[apps.index("config.systemd.services.nas-bootstrap-runtime-select = {") :]
        for unit in (
            "nas-bootstrap-authentik-secrets.service",
            "authentik-migrate.service",
            "authentik-worker.service",
            "authentik.service",
        ):
            self.assertIn(f'"{unit}"', selector)

    def test_application_service_selector_has_no_shadow_executable(self) -> None:
        apps = APPLICATIONS.read_text(encoding="utf-8")
        selector = apps[apps.index("config.systemd.services.nas-bootstrap-runtime-select = {") :]
        self.assertNotIn('pkgs.writeShellScript "nas-bootstrap-runtime-select"', selector)
        self.assertNotIn('rm -rf -- "/var/lib/$name"', selector)
        hardened = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("lib.mkOverride 40 runtimeSelector", hardened)

    def test_original_fixed_linux_password_is_overridden_not_relied_on(self) -> None:
        source = SYSTEMD.read_text(encoding="utf-8")
        self.assertIn("nas-bootstrap-administrator", source)
        hardened = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("lib.mkOverride 40 bootstrapAdministrator", hardened)


if __name__ == "__main__":
    unittest.main()
