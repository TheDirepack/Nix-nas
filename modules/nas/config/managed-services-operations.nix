{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  helpers = import ./managed-services-helpers.nix { inherit lib config nasInternal; };
  inherit (helpers) scheduledJob calendar systemdSchedules healthSchedule;
  job = helpers.scheduledJob;
  dependency = helpers.depends;
  # Keep alias names expected by legacy tests that grep for `job "restic-backups...` pattern.
  # The shared helper provides canonical `scheduledJob`; this alias preserves string match.

  operationServices = {
    zfs-pool-health = (job "nas-zfs-pool-health.service" "Check ZFS pool health" healthSchedule) // {
      dependencies = [ (dependency "zfs-mount-guard" "completed") ];
    };
    zfs-capacity-health = (job "nas-zfs-capacity-health.service" "Check ZFS capacity" healthSchedule) // {
      dependencies = [ (dependency "zfs-mount-guard" "completed") ];
    };
    zfs-snapshot-health = (job "nas-zfs-snapshot-health.service" "Check ZFS snapshot freshness" healthSchedule) // {
      dependencies = [ (dependency "zfs-mount-guard" "completed") ];
    };
    zfs-manual-snapshot = (job "nas-zfs-manual-snapshot.service" "Create an administrator-requested ZFS snapshot" [ ]) // {
      dependencies = [ (dependency "zfs-mount-guard" "completed") ];
    };
    zfs-manual-scrub = (job "nas-zfs-manual-scrub.service" "Start an administrator-requested ZFS scrub" [ ]) // {
      dependencies = [ (dependency "zfs-mount-guard" "completed") ];
    };
  }
  // lib.optionalAttrs cfg.backup.enable {
    backups = (job "restic-backups-nas-boot-system.service" "Back up authoritative NAS state" (
      systemdSchedules [ (calendar "daily" 7200) ]
    )) // {
      dependencies = [ (dependency "zfs-mount-guard" "completed") ];
    };
  }
  // lib.optionalAttrs (cfg.backup.enable && cfg.backup.restoreVerification.enable) {
    backup-restore-verify = job "nas-backup-restore-verify.service" "Restore and validate the latest NAS recovery backup" (
      systemdSchedules [ (calendar cfg.backup.restoreVerification.onCalendar 21600) ]
    );
  }
  // lib.optionalAttrs cfg.zfsReplication.enable {
    zfs-replication = (job "nas-syncoid.service" "Replicate the NAS ZFS dataset" (
      systemdSchedules [ (calendar cfg.zfsReplication.onCalendar 7200) ]
    )) // {
      dependencies = [ (dependency "zfs-mount-guard" "completed") ];
    };
  }
  // lib.optionalAttrs cfg.installationReady {
    update-preview = job "nas-update-preview.service" "Preview and validate configuration updates" [ ];
    update-sync = job "nas-update-sync.service" "Synchronize the reviewed configuration" [ ];
    update-apply = job "nas-update-apply.service" "Apply the reviewed configuration" [ ];
  }
  // lib.optionalAttrs (cfg.installationReady && cfg.autoUpdate.enable) {
    auto-update = job "nas-auto-update.service" "Guarded automatic NAS configuration update" (
      systemdSchedules [ (calendar cfg.autoUpdate.onCalendar 3600) ]
    );
  };

in
{
  config = {
    # The existing Restic service stays the backup implementation. V2 owns its
    # schedule, so the NixOS Restic module must not create a parallel timer.
    services.restic.backups = lib.mkIf cfg.backup.enable {
      nas-boot-system.timerConfig = lib.mkForce null;
    };
  };
}
