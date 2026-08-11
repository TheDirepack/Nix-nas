{ config, lib, pkgs, ... }:

let
  cfg = config.nas;
  desiredPath = "/var/lib/nas-control/services.yaml";
  markerPath = "/var/lib/nas-control/.managed-services-operational-schedules-seed-v2";
  schemaPath = "/etc/nas-control/managed-services-v3.schema.json";
  platformPath = "/etc/nas-control/platform-capabilities.json";
  v2Source = ../../../services;
  v2Python = pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
    defusedxml
    jsonschema
    ruamel-yaml
  ]);
  yamlFormat = pkgs.formats.yaml { };

  job = unit: name: {
    inherit name;
    managed = true;
    workload.kind = "job";
    runtime = { type = "systemd"; inherit unit; };
  };
  scheduledJob = unit: name: schedules: (job unit name) // {
    workload = { kind = "job"; inherit schedules; };
  };
  healthSchedule = [
    {
      calendar = "*-*-* 06:00";
      randomizedDelaySeconds = 1800;
      persistent = true;
    }
  ];

  operationalServices =
    lib.optionalAttrs (cfg.scheduler.backend == "systemd") {
      zfs-pool-health = scheduledJob
        "nas-zfs-pool-health.service"
        "Check ZFS pool health"
        healthSchedule;
      zfs-capacity-health = scheduledJob
        "nas-zfs-capacity-health.service"
        "Check ZFS capacity health"
        healthSchedule;
      zfs-snapshot-health = scheduledJob
        "nas-zfs-snapshot-health.service"
        "Check ZFS snapshot health"
        healthSchedule;
    }
    // lib.optionalAttrs (
      cfg.scheduler.backend == "systemd"
      && cfg.autoUpdate.enable
      && cfg.installationReady
    ) {
      automatic-updates = scheduledJob
        "nas-auto-update.service"
        "Run guarded automatic NAS configuration updates"
        [
          {
            calendar = cfg.autoUpdate.onCalendar;
            randomizedDelaySeconds = 3600;
            persistent = true;
          }
        ];
    }
    // lib.optionalAttrs (cfg.scheduler.backend == "systemd" && cfg.backup.enable) {
      backups = scheduledJob
        "restic-backups-nas-boot-system.service"
        "Back up critical NAS system and Managed Services V2 state"
        [
          {
            calendar = "daily";
            randomizedDelaySeconds = 7200;
            persistent = true;
          }
        ];
    }
    // lib.optionalAttrs (
      cfg.scheduler.backend == "systemd"
      && cfg.backup.enable
      && cfg.backup.restoreVerification.enable
    ) {
      backup-restore-verify = scheduledJob
        "nas-backup-restore-verify.service"
        "Restore and validate the latest NAS recovery backup"
        [
          {
            calendar = cfg.backup.restoreVerification.onCalendar;
            randomizedDelaySeconds = 21600;
            persistent = true;
          }
        ];
    }
    // lib.optionalAttrs (cfg.scheduler.backend == "systemd" && cfg.zfsReplication.enable) {
      zfs-replication = scheduledJob
        "nas-syncoid.service"
        "Replicate the NAS ZFS dataset with Syncoid"
        [
          {
            calendar = cfg.zfsReplication.onCalendar;
            randomizedDelaySeconds = 7200;
            persistent = true;
          }
        ];
    };

  seedFile = yamlFormat.generate "managed-services-operational-schedules-seed-v2.yaml" {
    schemaVersion = 3;
    services = operationalServices;
  };
in
{
  config = {
    # The Restic NixOS module can generate its own timer. Managed Services V2
    # owns the active schedule instead, so the native Restic service remains the
    # execution primitive while V2's generated timer is the sole scheduler.
    services.restic.backups = lib.mkIf cfg.backup.enable {
      nas-boot-system.timerConfig = lib.mkForce null;
    };

    systemd.services.nas-managed-services-seed = lib.mkIf (builtins.length (builtins.attrNames operationalServices) > 0) {
      environment.PYTHONPATH = "${v2Source}";
      postStart = lib.mkAfter ''
        ${v2Python}/bin/python ${v2Source}/nas_v2_bootstrap.py \
          --desired ${lib.escapeShellArg desiredPath} \
          --seed ${lib.escapeShellArg seedFile} \
          --marker ${lib.escapeShellArg markerPath} \
          --schema ${lib.escapeShellArg schemaPath} \
          --platform ${lib.escapeShellArg platformPath}
      '';
      serviceConfig.ReadWritePaths = lib.mkAfter [ "/var/lib/nas-control" ];
    };
  };
}
