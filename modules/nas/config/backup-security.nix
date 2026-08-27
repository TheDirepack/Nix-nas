{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  backupRoot = "/var/lib/nas-backup";
  backupStagePath = cfg.backup.stagingPath;
  restoreVerifyPath = cfg.backup.restoreVerification.targetPath;
  safeDirectChild = path:
    let
      prefix = backupRoot + "/";
      child = lib.removePrefix prefix path;
    in
      lib.hasPrefix prefix path
      && child != ""
      && !lib.hasInfix "/" child
      && child != "."
      && child != "..";
  safeBackupStagePath = safeDirectChild backupStagePath;
  safeRestoreVerifyPath = safeDirectChild restoreVerifyPath;
  secureBoundaryCheck = pkgs.writeShellScript "nas-backup-secure-boundary-check" ''
    set -euo pipefail

    backup_root=${lib.escapeShellArg backupRoot}
    stage_path=${lib.escapeShellArg backupStagePath}
    restore_path=${lib.escapeShellArg restoreVerifyPath}

    ${pkgs.coreutils}/bin/install -d -m 0700 -o root -g root "$backup_root"
    if [[ -L "$backup_root" || ! -d "$backup_root" ]]; then
      echo "Backup scratch root must be a regular directory, not a symlink: $backup_root" >&2
      exit 70
    fi
    root_owner="$(${pkgs.coreutils}/bin/stat -c '%u' -- "$backup_root")"
    root_mode="$(${pkgs.coreutils}/bin/stat -c '%a' -- "$backup_root")"
    [[ "$root_owner" == 0 ]] || {
      echo "Backup scratch root must be owned by root: $backup_root" >&2
      exit 70
    }
    (( (8#$root_mode & 8#022) == 0 )) || {
      echo "Backup scratch root must not be group/world writable: $backup_root" >&2
      exit 70
    }

    check_delete_target() {
      local label="$1" path="$2"
      [[ "$path" == "$backup_root/"* && "$path" != "$backup_root/" ]] || {
        echo "$label must be a dedicated child of $backup_root: $path" >&2
        exit 70
      }
      [[ "''${path#$backup_root/}" != */* ]] || {
        echo "$label must be a direct child of $backup_root: $path" >&2
        exit 70
      }
      if [[ -L "$path" ]]; then
        echo "$label must not be a symlink: $path" >&2
        exit 70
      fi
    }

    check_delete_target "Backup staging path" "$stage_path"
    check_delete_target "Restore verification target" "$restore_path"

    check_file() {
      local label="$1" path="$2"
      [[ -n "$path" ]] || return 0
      if [[ -L "$path" || ! -f "$path" ]]; then
        echo "$label must be a regular non-symlink file: $path" >&2
        exit 70
      fi
      owner="$(${pkgs.coreutils}/bin/stat -c '%u' -- "$path")"
      mode="$(${pkgs.coreutils}/bin/stat -c '%a' -- "$path")"
      [[ "$owner" == 0 ]] || {
        echo "$label must be owned by root: $path" >&2
        exit 70
      }
      (( (8#$mode & 8#077) == 0 )) || {
        echo "$label must not grant group/other permissions: $path" >&2
        exit 70
      }
      [[ -s "$path" ]] || {
        echo "$label must not be empty: $path" >&2
        exit 70
      }
    }

    check_file "Restic password file" ${lib.escapeShellArg cfg.backup.passwordFile}
    check_file "Restic repository file" ${lib.escapeShellArg cfg.backup.repositoryFile}
    check_file "rclone config file" ${lib.escapeShellArg cfg.backup.remote.rcloneConfigFile}
  '';
  reviewedSyncoidArgs =
    lib.optional cfg.zfsReplication.recursive "--recursive"
    ++ lib.optional cfg.zfsReplication.useExistingSnapshots "--no-sync-snap"
    ++ cfg.zfsReplication.extraArgs
    ++ [ "--sendoptions=w" cfg.zfsDataset cfg.zfsReplication.target ];
in
{
  config = {
    assertions = [
      {
        assertion = !cfg.backup.enable || safeBackupStagePath;
        message = "nas.backup.stagingPath is recursively deleted and must be a dedicated direct child of /var/lib/nas-backup.";
      }
      {
        assertion = !cfg.backup.enable || !cfg.backup.restoreVerification.enable || safeRestoreVerifyPath;
        message = "nas.backup.restoreVerification.targetPath is recursively deleted and must be a dedicated direct child of /var/lib/nas-backup.";
      }
      {
        assertion = !cfg.zfsReplication.enable || cfg.zfsEncryption.enable;
        message = "nas.zfsReplication requires encrypted ZFS so replication can use a raw encrypted send.";
      }
      {
        assertion = !cfg.zfsReplication.enable || lib.all (
          argument: argument != "--sendoptions" && !lib.hasPrefix "--sendoptions=" argument
        ) cfg.zfsReplication.extraArgs;
        message = "nas.zfsReplication.extraArgs may not override Syncoid send options; encrypted replication always uses a raw send.";
      }
    ];

    services.restic.backups = lib.mkIf cfg.backup.enable {
      nas-boot-system.backupPrepareCommand = lib.mkBefore ''
        ${secureBoundaryCheck}
      '';
    };

    systemd.services.nas-backup-restore-verify = lib.mkIf (
      cfg.backup.enable && cfg.backup.restoreVerification.enable
    ) {
      script = lib.mkBefore ''
        ${secureBoundaryCheck}
      '';
    };

    systemd.services.nas-syncoid = lib.mkIf cfg.zfsReplication.enable {
      serviceConfig.ExecStart = lib.mkOverride 40 (
        "${pkgs.sanoid}/bin/syncoid ${lib.escapeShellArgs reviewedSyncoidArgs}"
      );
    };
  };
}