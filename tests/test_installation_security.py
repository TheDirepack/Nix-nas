from __future__ import annotations

import unittest

from repo_test_utils import text


class InstallationSecurityContracts(unittest.TestCase):
    def test_install_ready_rejects_default_host_id_and_empty_trusted_interfaces(self) -> None:
        validation = text("modules/nas/config/validation.nix")
        self.assertIn('config.networking.hostId != "00000000"', validation)
        self.assertIn("!cfg.installationReady || cfg.trustedInterfaces != [ ]", validation)

    def test_repository_hardware_stub_cannot_be_install_ready(self) -> None:
        module = text("modules/nas/config/installation-security.nix")
        hardware = text("hardware-configuration.nix")
        default = text("modules/nas/default.nix")
        self.assertIn("./config/installation-security.nix", default)
        self.assertIn("nas.testing.hardwareConfigurationStub = true;", hardware)
        self.assertIn("!cfg.testing.hardwareConfigurationStub", module)
        self.assertIn("nixos-generate-config", module)

    def test_install_ready_requires_real_recovery_path(self) -> None:
        module = text("modules/nas/config/installation-security.nix")
        self.assertIn('lib.elem "nas-administrators"', module)
        self.assertIn("user.openssh.authorizedKeys.keys", module)
        self.assertIn("user.openssh.authorizedKeys.keyFiles", module)
        self.assertIn("cfg.recovery.consoleOrKvmAvailable", module)
        self.assertIn("installationReady requires a usable recovery path", module)

    def test_unencrypted_install_ready_requires_explicit_acknowledgement(self) -> None:
        module = text("modules/nas/config/installation-security.nix")
        ready = text("tests/nixos/ready.nix")
        self.assertIn("cfg.zfsEncryption.enable", module)
        self.assertIn("cfg.zfsEncryption.disabledAcknowledged", module)
        self.assertIn("native ZFS encryption is DISABLED", module)
        self.assertIn("zfsEncryption.disabledAcknowledged = lib.mkForce true;", ready)

    def test_secret_file_preflight_fails_closed_before_runtime_selection(self) -> None:
        module = text("modules/nas/config/secret-file-preflight.nix")
        default = text("modules/nas/default.nix")
        self.assertIn("./config/secret-file-preflight.nix", default)
        self.assertIn('[[ ! -L "$path" ]]', module)
        self.assertIn('[[ -f "$path" ]]', module)
        self.assertIn("stat -c '%u'", module)
        self.assertIn("stat -c '%g'", module)
        self.assertIn("stat -c '%a'", module)
        self.assertIn("permissions & 8#007", module)
        self.assertIn("permissions & ~allowed", module)
        self.assertIn('getent group "$group_policy"', module)
        self.assertIn('before = [ "nas-bootstrap-runtime-select.service" ];', module)
        self.assertIn('requires = [ "nas-secret-file-preflight.service" ];', module)
        self.assertIn(
            'require_private_file ${lib.escapeShellArg cfg.secrets.keepassDatabase} "permanent KDBX" 0660 admin nas-administrators',
            module,
        )
        self.assertIn(
            'require_private_file ${lib.escapeShellArg cfg.secrets.keepassKeyFile} "KeePass key file" 0600 admin -',
            module,
        )
        for label in (
            "bootstrap KDBX",
            "bootstrap KDBX password",
            "bootstrap Authentik environment",
            "bootstrap Authentik API token",
            "permanent KDBX",
            "KeePass key file",
            "permanent Authentik environment",
            "permanent Authentik API token",
        ):
            self.assertIn(label, module)

    def test_direct_nas_secrets_unlock_checks_file_metadata(self) -> None:
        source = text("modules/nas/internal/secret-tools.nix")
        self.assertIn("require_private_credential_file()", source)
        self.assertIn('[[ ! -L "$path" ]]', source)
        self.assertIn('[[ -f "$path" ]]', source)
        self.assertIn("stat -c '%u'", source)
        self.assertIn("stat -c '%g'", source)
        self.assertIn("stat -c '%a'", source)
        self.assertIn("permissions & 8#007", source)
        self.assertIn("permissions & ~8#660", source)
        self.assertIn('getent group "$shared_group"', source)
        self.assertIn(
            'require_private_credential_file "$database" "KeePassXC database" nas-administrators', source
        )
        self.assertIn('require_private_credential_file "$key_file" "KeePassXC key file"', source)
        self.assertLess(source.index("require_database\n"), source.index("IFS= read -r keepass_password"))

    def test_bootstrap_worker_has_only_required_permanent_kdbx_group(self) -> None:
        setup_security = text("modules/nas/config/setup-security.nix")
        bootstrap = text("modules/nas/config/bootstrap-security.nix")
        self.assertIn("--append --groups nas-administrators nas-bootstrap", setup_security)
        self.assertIn("--shell /run/current-system/sw/bin/nologin", bootstrap)
        self.assertIn("passwd --lock nas-bootstrap", bootstrap)

    def test_direct_secret_signal_handlers_terminate(self) -> None:
        source = text("modules/nas/internal/secret-tools.nix")
        self.assertIn("trap 'cleanup_password; exit 129' HUP", source)
        self.assertIn("trap 'cleanup_password; exit 130' INT", source)
        self.assertIn("trap 'cleanup_password; exit 143' TERM", source)

    def test_secret_tokens_are_bounded_and_generated_keys_revalidated(self) -> None:
        source = text("modules/nas/internal/secret-tools.nix")
        self.assertGreaterEqual(source.count("''${#token} > 4096"), 3)
        self.assertIn("''${#value} > 4096", source)
        self.assertIn('require_secret_hex "$grafana_secret_key" 64', source)
        self.assertIn('require_secret_hex "$nut_webgui_server_key" 64', source)
        self.assertIn('require_secret_hex "$zfs_dataset_key" 64', source)

    def test_first_run_bootstrap_authority_also_checks_private_root_files(self) -> None:
        first_start = text("services/nas_first_start.py")
        self.assertIn("def _regular_root_file", first_start)
        self.assertIn("info.st_uid == 0", first_start)
        self.assertIn("stat.S_IMODE(info.st_mode) & 0o077", first_start)
        self.assertIn("Disposable bootstrap KDBX is missing or unsafe", first_start)
        self.assertIn("Bootstrap Authentik API token staging is missing or unsafe", first_start)


if __name__ == "__main__":
    unittest.main()
