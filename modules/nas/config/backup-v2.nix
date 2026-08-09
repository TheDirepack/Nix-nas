{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  effectivePath = "/run/nas-control/effective-endpoints.json";
in
{
  config = lib.mkIf cfg.backup.enable {
    # Keep the native NixOS Restic service/systemd timer. Runtime-managed V2
    # resources are appended through the module's supported dynamicFilesFrom
    # hook, which feeds Restic --files-from. Snapshot/native resources are not
    # emitted until nas-backup-v2 has created a consistent source for them.
    services.restic.backups.nas-boot-system.dynamicFilesFrom = ''
      #!${pkgs.runtimeShell}
      set -eu
      exec ${nasInternal.nasPythonApplication}/bin/nas-backup-v2 files --effective ${effectivePath}
    '';

    systemd.services.restic-backups-nas-boot-system = {
      after = [ "nas-managed-services-reconcile.service" ];
      wants = [ "nas-managed-services-reconcile.service" ];
    };
  };
}
