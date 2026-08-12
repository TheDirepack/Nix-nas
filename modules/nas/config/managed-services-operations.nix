{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  desiredPath = "/var/lib/nas-control/services.yaml";
  markerPath = "/var/lib/nas-control/.managed-services-operations-seed-v2";
  schemaPath = "/etc/nas-control/managed-services-v3.schema.json";
  platformPath = "/etc/nas-control/platform-capabilities.json";
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
  yamlFormat = pkgs.formats.yaml { };

  job = unit: name: schedules: {
    inherit name;
    managed = true;
    workload = {
      kind = "job";
      inherit schedules;
    };
    runtime = {
      type = "systemd";
      inherit unit;
    };
  };

  dependency = service: condition: { inherit service condition; };

  calendar = expression: randomizedDelaySeconds: {
    calendar = expression;
    inherit randomizedDelaySeconds;
    persistent = true;
  };

  systemdSchedules = schedules: lib.optionals (cfg.scheduler.backend == "systemd") schedules;
  healthSchedule = systemdSchedules [ (calendar "*-*-* 06:00" 1800) ];

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
