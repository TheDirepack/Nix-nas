{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cfg
    protectedServiceUnits
  ;
  healthTimer = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "*-*-* 06:00";
      RandomizedDelaySec = "30m";
      Persistent = true;
    };
  };
in
{
  config = {
    systemd.timers = {
      nas-zfs-pool-health = lib.mkIf (cfg.scheduler.backend == "systemd") healthTimer;
      nas-zfs-capacity-health = lib.mkIf (cfg.scheduler.backend == "systemd") healthTimer;
      nas-zfs-snapshot-health = lib.mkIf (cfg.scheduler.backend == "systemd") healthTimer;

      nas-auto-update = lib.mkIf (cfg.scheduler.backend == "systemd" && cfg.autoUpdate.enable && cfg.installationReady) {
        wantedBy = lib.mkOverride 90 [ ];
        timerConfig = {
          OnCalendar = cfg.autoUpdate.onCalendar;
          RandomizedDelaySec = "1h";
          Persistent = true;
        };
      };

      nas-identity-sync = {
        wantedBy = [ "nas-protected-services.target" ];
        partOf = [ "nas-protected-services.target" ];
        timerConfig = {
          OnUnitActiveSec = cfg.identity.syncInterval;
          Unit = "nas-identity-sync.service";
          Persistent = false;
        };
      };

      nas-syncthing-sync = lib.mkIf cfg.syncthing.enable {
        wantedBy = lib.mkOverride 90 [ ];
        partOf = [ "nas-protected-services.target" ];
        timerConfig = {
          OnUnitActiveSec = cfg.identity.syncInterval;
          Unit = "nas-syncthing-sync.service";
          Persistent = false;
        };
      };

      restic-backups-nas-boot-system = lib.mkIf cfg.backup.enable {
        wantedBy = lib.mkOverride 90 [ ];
      };
      nas-backup-restore-verify = lib.mkIf (
        cfg.backup.enable
        && cfg.backup.restoreVerification.enable
        && cfg.scheduler.backend == "systemd"
      ) {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = cfg.backup.restoreVerification.onCalendar;
          RandomizedDelaySec = "6h";
          Persistent = true;
        };
      };

      nas-syncoid = lib.mkIf (cfg.zfsReplication.enable && cfg.scheduler.backend == "systemd") {
        wantedBy = [ "nas-protected-services.target" ];
        partOf = [ "nas-protected-services.target" ];
        timerConfig = {
          OnCalendar = cfg.zfsReplication.onCalendar;
          RandomizedDelaySec = "2h";
          Persistent = true;
        };
      };
    };

    systemd.targets.nas-protected-services = {
      description = "NAS core services enabled after KeePassXC secret activation";
      requires = protectedServiceUnits;
      wants = [ "nas-feature-apply.service" "network-online.target" ];
      after = [ "network-online.target" ] ++ protectedServiceUnits;
    };
  };
}
