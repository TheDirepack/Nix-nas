{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    aiStorageRoot
    cfg
    copypartyUserConfigDir
    sanoidPolicy
  ;
  backupStage = cfg.backup.stagingPath;
  v2Source = ../../../services;
  v2BackupInventory = "/run/nas-control/backup-resources.json";
  v2BackupRuntimePaths = "/run/nas-control/restic-v2-runtime-paths";
  v2BackupRuntimeState = "/run/nas-control/backup-runtime-state.json";
  localResticRepository =
    if cfg.backup.localRepository != "" then cfg.backup.localRepository
    else "${cfg.zfsRoot}/backups/restic-system";
  resticRepository =
    if cfg.backup.repositoryFile != ""
    then { repositoryFile = cfg.backup.repositoryFile; }
    else { repository = localResticRepository; };
  resticRepositoryArgs =
    if cfg.backup.repositoryFile != ""
    then [ "--repository-file" cfg.backup.repositoryFile ]
    else [ "--repo" localResticRepository ];
  resticCommand = "${pkgs.restic}/bin/restic ${lib.escapeShellArgs resticRepositoryArgs}";
  restoreVerifyPath = cfg.backup.restoreVerification.targetPath;
  syncoidArgs =
    lib.optional cfg.zfsReplication.recursive "--recursive"
    ++ lib.optional cfg.zfsReplication.useExistingSnapshots "--no-sync-snap"
    ++ cfg.zfsReplication.extraArgs
    ++ [ cfg.zfsDataset cfg.zfsReplication.target ];
in
{
  config = {
    services.avahi = lib.mkIf (cfg.trustedInterfaces != [ ]) {
      enable = true;
      nssmdns4 = true;
      openFirewall = false;
      allowInterfaces = cfg.trustedInterfaces;
      wideArea = false;
      publish = {
        enable = true;
        addresses = true;
        workstation = true;
      };
      extraServiceFiles.nas-services = ''
        <?xml version="1.0" standalone='no'?>
        <!DOCTYPE service-group SYSTEM "avahi-service.dtd">
        <service-group>
          <name replace-wildcards="yes">%h NAS</name>
          <service>
            <type>_https._tcp</type>
            <port>443</port>
            <txt-record>path=/</txt-record>
          </service>
          <service>
            <type>_webdavs._tcp</type>
            <port>443</port>
            <txt-record>path=/dav/</txt-record>
          </service>
          ${lib.optionalString cfg.tftp.enable ''
          <service>
            <type>_tftp._udp</type>
            <port>${toString cfg.tftp.port}</port>
            <txt-record>path=/tftp/</txt-record>
          </service>
          ''}
        </service-group>
      '';
    };

    services.sanoid = {
      enable = cfg.scheduler.backend == "systemd";
      interval = "hourly";
      templates.production = sanoidPolicy;
      datasets.${cfg.zfsDataset} = {
        use_template = [ "production" ];
        recursive = "zfs";
      };
    };

    services.zfs = {
      autoScrub = {
        enable = cfg.scheduler.backend == "systemd";
        interval = "Sun *-*-1..7 03:00";
        randomizedDelaySec = "2h";
      };
      trim = {
        enable = cfg.zfsTrimEnable && cfg.scheduler.backend == "systemd";
        interval = "Wed 03:00";
        randomizedDelaySec = "2h";
      };
      zed.enableMail = false;
    };

    services.smartd.enable = lib.mkDefault false;

    services.restic.backups = lib.mkIf cfg.backup.enable {
      nas-boot-system = ({
        initialize = true;
        inhibitsSleep = true;
        paths = [
          "/boot"
          "/etc/machine-id"
          "/etc/ssh"
          "/var/lib/nixos"
          cfg.configurationDir
          cfg.secrets.keepassDatabase
          "/var/lib/caddy"
          "/var/lib/authentik"
          copypartyUserConfigDir
          "/var/lib/nas-control"
          "/var/lib/nas-identity-sync"
          "/var/lib/nas-setup"
        ]
        ++ lib.optionals cfg.networking.enable [
          "/etc/NetworkManager/system-connections"
        ]
        ++ lib.optionals (cfg.networking.enable && cfg.networking.firewall.enable) [
          "/var/lib/nas-firewall"
        ]
        ++ lib.optionals cfg.observability.enable [
          "/var/lib/nas-alert-router"
        ]
        ++ lib.optionals (cfg.observability.enable && cfg.observability.grafana.enable) [
          "/var/lib/grafana"
        ]
        ++ lib.optionals cfg.observability.ntfy.enable [
          "/var/lib/ntfy-sh"
        ]
        ++ lib.optionals cfg.ai.enable [
          "/var/lib/nas-llama-swap"
          "/var/lib/open-webui"
          "${aiStorageRoot}/downloader-config"
        ];
        dynamicFilesFrom = ''
          #!${pkgs.runtimeShell}
          ${pkgs.coreutils}/bin/cat ${lib.escapeShellArg v2BackupRuntimePaths}
        '';
        passwordFile = cfg.backup.passwordFile;
        backupPrepareCommand = ''
          #!${pkgs.runtimeShell}
          set -euo pipefail
          backup_stage=${lib.escapeShellArg backupStage}
          rm -rf "$backup_stage"
          install -d -m 0700 "$backup_stage"
          available=$(${pkgs.coreutils}/bin/df --output=avail -B1 "$backup_stage" | ${pkgs.coreutils}/bin/tail -n 1 | ${pkgs.coreutils}/bin/tr -d "[:space:]")
          [[ "$available" =~ ^[0-9]+$ && "$available" -ge ${toString cfg.backup.stagingMinFreeBytes} ]] || { echo "Insufficient free space in $backup_stage" >&2; exit 1; }
          ${lib.optionalString (cfg.backup.repositoryFile == "") ''
          install -d -m 0700 ${lib.escapeShellArg localResticRepository}
          ''}

          # Resolve the resource-oriented V2 inventory immediately before Restic
          # starts. This synchronously creates ZFS snapshots and executes generic
          # native-dump preparation jobs, then emits only the exact paths Restic
          # should consume. Application identities are not handled here.
          ${pkgs.python3}/bin/python3 ${v2Source}/nas_v2_backup_runtime.py prepare \
            --inventory ${lib.escapeShellArg v2BackupInventory} \
            --paths ${lib.escapeShellArg v2BackupRuntimePaths} \
            --state ${lib.escapeShellArg v2BackupRuntimeState} \
            --zfs ${pkgs.zfs}/bin/zfs \
            --systemctl ${pkgs.systemd}/bin/systemctl
        '';
        backupCleanupCommand = ''
          #!${pkgs.runtimeShell}
          set -euo pipefail
          ${pkgs.python3}/bin/python3 ${v2Source}/nas_v2_backup_runtime.py cleanup \
            --paths ${lib.escapeShellArg v2BackupRuntimePaths} \
            --state ${lib.escapeShellArg v2BackupRuntimeState} \
            --zfs ${pkgs.zfs}/bin/zfs
          rm -rf ${lib.escapeShellArg backupStage}
        '';
        timerConfig = if cfg.scheduler.backend == "systemd" then {
          OnCalendar = "daily";
          RandomizedDelaySec = "2h";
          Persistent = true;
        } else null;
        pruneOpts = [
          "--keep-daily 14"
          "--keep-weekly 8"
          "--keep-monthly 12"
          "--keep-yearly 3"
        ];
        runCheck = true;
        checkOpts = [ "--read-data-subset=1%" ];
      } // resticRepository);
    };

    systemd.services.restic-backups-nas-boot-system = lib.mkIf cfg.backup.enable {
      requires = [ "nas-managed-services-reconcile.service" ]
        ++ lib.optional (cfg.backup.repositoryFile == "") "nas-zfs-mount-guard.service";
      after = [ "nas-managed-services-reconcile.service" ]
        ++ lib.optional (cfg.backup.repositoryFile == "") "nas-zfs-mount-guard.service";
      unitConfig = {
        RequiresMountsFor = [ backupStage ] ++ lib.optional (cfg.backup.repositoryFile == "") cfg.zfsRoot;
        ConditionPathExists = [ cfg.backup.passwordFile v2BackupInventory ];
      };
    };

    systemd.services.nas-backup-restore-verify = lib.mkIf (
      cfg.backup.enable && cfg.backup.restoreVerification.enable
    ) {
      description = "Restore and validate the latest NAS recovery backup in isolation";
      onFailure = nasInternal.failureAlert;
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      unitConfig.RequiresMountsFor = [ restoreVerifyPath ]
        ++ lib.optional (cfg.backup.repositoryFile == "") localResticRepository;
      serviceConfig = {
        Type = "oneshot";
        Nice = 15;
        IOSchedulingClass = "idle";
        TimeoutStartSec = "6h";
        UMask = "0077";
      };
      path = [ pkgs.coreutils ];
      script = ''
        set -euo pipefail
        verify_root=${lib.escapeShellArg restoreVerifyPath}
        restore_root="$verify_root/restored"
        cleanup() {
          rm -rf "$verify_root"
        }
        trap cleanup EXIT
        rm -rf "$verify_root"
        install -d -m 0711 "$verify_root"
        install -d -m 0700 "$restore_root"
        available=$(${pkgs.coreutils}/bin/df --output=avail -B1 "$verify_root" | ${pkgs.coreutils}/bin/tail -n 1 | ${pkgs.coreutils}/bin/tr -d "[:space:]")
        [[ "$available" =~ ^[0-9]+$ && "$available" -ge ${toString cfg.backup.stagingMinFreeBytes} ]] || { echo "Insufficient free space in $verify_root" >&2; exit 1; }
        export RESTIC_PASSWORD_FILE=${lib.escapeShellArg cfg.backup.passwordFile}
        ${resticCommand} restore latest --target "$restore_root"

        # Validate every compiled V2 backup resource generically. Native-dump
        # artifacts get format-aware integrity checks selected from their data;
        # ordinary filesystem resources are only checked for successful restore
        # so arbitrary user files are never interpreted as application state.
        ${pkgs.python3}/bin/python3 ${v2Source}/nas_v2_backup_verify.py \
          --inventory ${lib.escapeShellArg v2BackupInventory} \
          --restore-root "$restore_root" \
          --pg-restore ${config.services.postgresql.package}/bin/pg_restore

        # These are host recovery substrate rather than application resources.
        [[ -s "$restore_root${cfg.secrets.keepassDatabase}" ]]
        [[ -d "$restore_root/var/lib/nas-control" ]]
      '';
    };

    systemd.services.nas-syncoid = lib.mkIf cfg.zfsReplication.enable {
      description = "Replicate the NAS ZFS dataset with Syncoid";
      onFailure = nasInternal.failureAlert;
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" "network-online.target" ];
      wants = [ "network-online.target" ];
      unitConfig = {
        RequiresMountsFor = lib.optional (!cfg.zfsEncryption.enable) cfg.zfsRoot;
        AssertPathIsMountPoint = cfg.zfsRoot;
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.sanoid}/bin/syncoid ${lib.escapeShellArgs syncoidArgs}";
        Nice = 10;
        IOSchedulingClass = "best-effort";
        IOSchedulingPriority = 7;
      };
    };
  };
}
