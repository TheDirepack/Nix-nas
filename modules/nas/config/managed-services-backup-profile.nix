{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  profilePath = pkgs.writeText "nas-resticprofile.json" (builtins.toJSON {
    version = "1";
    "nas-boot-system" = {
      # This local lock covers the complete backup/check/retention chain in
      # addition to Restic's repository lock.  The V2 systemd timer remains the
      # one schedule authority; resticprofile is deliberately not scheduled.
      lock = "/run/restic-backups-nas-boot-system/resticprofile.lock";
      backup = {
        "files-from" = [ "/run/restic-backups-nas-boot-system/includes" ];
        "check-after" = true;
      };
      retention = {
        "after-backup" = true;
        "before-backup" = false;
        prune = true;
        "keep-daily" = 14;
        "keep-weekly" = 8;
        "keep-monthly" = 12;
        "keep-yearly" = 3;
      };
      check = {
        "read-data-subset" = "1%";
      };
    };
  });
in
{
  config = lib.mkIf cfg.backup.enable {
    environment.systemPackages = [ pkgs.resticprofile ];

    # Keep the NixOS Restic module's useful native preStart/postStop plumbing:
    # it initializes the repository, materializes the static+V2 files-from
    # list, and invokes the NAS-specific ZFS/native-dump prepare/cleanup hooks.
    # Replace only its generic Restic command chain (backup, unlock,
    # forget/prune, check) with resticprofile.
    systemd.services.restic-backups-nas-boot-system.serviceConfig.ExecStart = lib.mkForce [
      "${pkgs.resticprofile}/bin/resticprofile --config ${profilePath} nas-boot-system.backup"
    ];
  };
}
