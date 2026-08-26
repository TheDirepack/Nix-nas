from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class BackupDomainArchitectureTests(unittest.TestCase):
    def test_root_restic_backup_never_traverses_encrypted_zfs(self) -> None:
        module = read("modules/nas/config/backup-domains.nix")
        self.assertIn('paths = lib.mkOverride 40 [\n          "/"\n          "/boot"', module)
        self.assertIn("dynamicFilesFrom = lib.mkOverride 40 null;", module)
        self.assertIn('"--one-file-system"', module)
        self.assertIn('"--tag=root-control-plane"', module)
        self.assertIn("cfg.zfsRoot", module)
        self.assertIn('"/var/lib/postgresql"', module)
        self.assertIn('"/var/lib/nas-operational/postgresql"', module)
        self.assertNotIn("nas_v2_backup.py", module)
        self.assertNotIn("backup-resources.json", module)

    def test_root_backup_uses_consistent_postgresql_dump_instead_of_live_pages(self) -> None:
        module = read("modules/nas/config/backup-domains.nix")
        self.assertIn('rootControlDatabaseDump = "${rootControlArtifactDir}/authentik.pgdump"', module)
        self.assertIn("pg_dump --format=custom authentik", module)
        self.assertIn("pg_restore --list", module)
        self.assertIn("cfg.secrets.keepassDatabase", module)
        self.assertIn('"/var/lib/nas-operational/postgresql"', module)

    def test_root_recovery_repository_is_independent_by_default(self) -> None:
        module = read("modules/nas/config/backup-domains.nix")
        options = read("modules/nas/options/operations.nix")
        self.assertIn("samePoolRepository", module)
        self.assertIn("cfg.backup.allowSamePoolRepository", module)
        self.assertIn("must be stored independently", module)
        self.assertIn("allowSamePoolRepository", options)
        self.assertIn("rollback-only", options)

    def test_restic_credential_files_are_fail_closed(self) -> None:
        module = read("modules/nas/config/backup-domains.nix")
        self.assertIn('secureCredentialCheck = pkgs.writeShellScript "nas-backup-secure-credential-check"', module)
        self.assertIn('[[ -L "$path" || ! -f "$path" ]]', module)
        self.assertIn('stat -c \'%u\'', module)
        self.assertIn('stat -c \'%a\'', module)
        self.assertIn('(8#$mode & 8#077)', module)
        self.assertIn('check_file "Restic password file"', module)
        self.assertIn('check_file "Restic repository file"', module)
        self.assertGreaterEqual(module.count("${secureCredentialCheck}"), 2)

    def test_restore_verification_scratch_is_confined_before_recursive_delete(self) -> None:
        module = read("modules/nas/config/backup-domains.nix")
        self.assertIn('lib.hasPrefix "/var/lib/nas-backup/" restoreVerifyPath', module)
        self.assertIn('!lib.hasInfix "/../" restoreVerifyPath', module)
        self.assertIn('restoreVerifyPath != rootControlArtifactDir', module)
        self.assertIn('!lib.hasPrefix "${rootControlArtifactDir}/" restoreVerifyPath', module)
        self.assertIn('!lib.hasPrefix "${restoreVerifyPath}/" rootControlArtifactDir', module)
        self.assertIn('!cfg.backup.restoreVerification.enable || safeRestoreVerifyPath', module)
        self.assertIn('rm -rf -- "$verify_root"', module)

    def test_encrypted_zfs_domain_uses_raw_syncoid_send(self) -> None:
        module = read("modules/nas/config/backup-domains.nix")
        storage = read("modules/nas/config/storage-monitoring.nix")
        self.assertIn('lib.optional cfg.zfsEncryption.enable "--sendoptions=w"', module)
        self.assertIn('lib.filter (argument: !(lib.hasPrefix "--sendoptions" argument))', module)
        self.assertIn("systemd.services.nas-syncoid.serviceConfig.ExecStart = lib.mkOverride 40", module)
        self.assertIn("!cfg.zfsReplication.enable || cfg.zfsEncryption.enable", module)
        self.assertIn("${pkgs.sanoid}/bin/syncoid", storage)
        self.assertIn("cfg.zfsDataset cfg.zfsReplication.target", storage)

    def test_root_restore_rejects_copied_v2_authority(self) -> None:
        module = read("modules/nas/config/backup-domains.nix")
        self.assertIn("services.yaml", module)
        self.assertIn("Root Restic backup unexpectedly contains the ZFS V2 desired-state authority", module)

    def test_per_app_backup_scope_is_not_a_configuration_authority(self) -> None:
        options = read("modules/nas/options/operations.nix")
        self.assertNotIn("scope = lib.mkOption", options)
        self.assertNotIn('"config-only" "all"', options)

    def test_backup_domain_override_is_loaded_after_legacy_storage_module(self) -> None:
        default = read("modules/nas/default.nix")
        storage_position = default.index("./config/storage-monitoring.nix")
        domain_position = default.index("./config/backup-domains.nix")
        self.assertLess(storage_position, domain_position)


if __name__ == "__main__":
    unittest.main()
