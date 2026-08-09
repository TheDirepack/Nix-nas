{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  effectivePath = "/run/nas-control/effective-endpoints.json";
  snapshotState = "/run/nas-backup-v2/snapshots.json";
in
{
  config = lib.mkIf cfg.backup.enable {
    # Keep the native NixOS Restic service/systemd timer. Runtime-managed V2
    # resources are appended through the module's supported dynamicFilesFrom
    # hook. The helper creates exact temporary ZFS snapshots only for resources
    # that request snapshot consistency and emits their read-only .zfs views.
    services.restic.backups.nas-boot-system.dynamicFilesFrom = ''
      #!${pkgs.runtimeShell}
      set -eu
      exec ${nasInternal.nasPythonApplication}/bin/nas-backup-v2 prepare-files \
        --effective ${effectivePath} \
        --state ${snapshotState}
    '';

    systemd.services.restic-backups-nas-boot-system = {
      after = [ "nas-managed-services-reconcile.service" ];
      wants = [ "nas-managed-services-reconcile.service" ];
      # The Restic module's own postStop handles staging/files-from cleanup.
      # Append exact V2 snapshot cleanup after it; the helper only accepts
      # snapshots in its generated namespace and never uses recursive destroy.
      postStop = lib.mkAfter ''
        ${nasInternal.nasPythonApplication}/bin/nas-backup-v2 cleanup \
          --state ${snapshotState}
      '';
    };
  };
}
