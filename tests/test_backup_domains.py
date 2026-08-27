from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class BackupSecurityTests(unittest.TestCase):
    def test_main_backup_implementation_is_preserved(self) -> None:
        default = read("modules/nas/default.nix")
        storage = read("modules/nas/config/storage-monitoring.nix")
        self.assertIn("./config/storage-monitoring.nix", default)
        self.assertIn("./config/backup-security.nix", default)
        self.assertNotIn("backup-domains.nix", default)
        self.assertIn("services.restic.backups", storage)
        self.assertIn("nas_v2_backup.py", storage)

    def test_restic_and_rclone_credential_files_are_fail_closed(self) -> None:
        module = read("modules/nas/config/backup-security.nix")
        self.assertIn('secureBoundaryCheck = pkgs.writeShellScript "nas-backup-secure-boundary-check"', module)
        self.assertIn('[[ -L "$path" || ! -f "$path" ]]', module)
        self.assertIn("stat -c '%u'", module)
        self.assertIn("stat -c '%a'", module)
        self.assertIn("(8#$mode & 8#077)", module)
        for label in ("Restic password file", "Restic repository file", "rclone config file"):
            self.assertIn(f'check_file "{label}"', module)
        # Guard whole option subtrees. Child-level mkIf definitions can leave
        # empty Restic/systemd submodules behind when the feature is disabled.
        self.assertIn("services.restic.backups = lib.mkIf cfg.backup.enable", module)
        self.assertNotIn("nas-boot-system.backupPrepareCommand = lib.mkIf", module)
        self.assertIn("systemd.services.nas-backup-restore-verify = lib.mkIf", module)
        self.assertNotIn("systemd.services.nas-backup-restore-verify.script = lib.mkIf", module)

    def test_recursive_delete_scratch_is_confined_to_private_direct_children(self) -> None:
        module = read("modules/nas/config/backup-security.nix")
        self.assertIn('backupRoot = "/var/lib/nas-backup";', module)
        self.assertIn("safeBackupStagePath = safeDirectChild backupStagePath", module)
        self.assertIn("safeRestoreVerifyPath = safeDirectChild restoreVerifyPath", module)
        self.assertIn('!lib.hasInfix "/" child', module)
        self.assertIn("!cfg.backup.enable || safeBackupStagePath", module)
        self.assertIn("!cfg.backup.restoreVerification.enable || safeRestoreVerifyPath", module)
        self.assertIn('[[ -L "$backup_root" || ! -d "$backup_root" ]]', module)
        self.assertIn("(8#$root_mode & 8#022)", module)
        self.assertIn('check_delete_target "Backup staging path"', module)
        self.assertIn('check_delete_target "Restore verification target"', module)

    def test_encrypted_zfs_replication_uses_raw_syncoid_send(self) -> None:
        module = read("modules/nas/config/backup-security.nix")
        storage = read("modules/nas/config/storage-monitoring.nix")
        self.assertIn('"--sendoptions=w"', module)
        self.assertIn('argument != "--sendoptions"', module)
        self.assertIn('!lib.hasPrefix "--sendoptions=" argument', module)
        self.assertIn("systemd.services.nas-syncoid = lib.mkIf cfg.zfsReplication.enable", module)
        self.assertNotIn("systemd.services.nas-syncoid.serviceConfig.ExecStart = lib.mkIf", module)
        self.assertIn("!cfg.zfsReplication.enable || cfg.zfsEncryption.enable", module)
        self.assertIn("${pkgs.sanoid}/bin/syncoid", storage)

    def test_existing_same_pool_recovery_policy_remains_authoritative(self) -> None:
        validation = read("modules/nas/config/validation.nix")
        options = read("modules/nas/options/operations.nix")
        self.assertIn("cfg.backup.allowSamePoolRepository", validation)
        self.assertIn("same-pool Restic repository", validation)
        self.assertIn("allowSamePoolRepository", options)
        self.assertIn("rollback-only", options)


if __name__ == "__main__":
    unittest.main()
