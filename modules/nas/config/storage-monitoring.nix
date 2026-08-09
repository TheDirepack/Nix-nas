{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    aiStorageRoot
    cfg
    copypartyUserConfigDir
    sanoidPolicy
    syncthingConfigDir
    vaultwardenBackupDir
  ;
  backupStage = cfg.backup.stagingPath;
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
          backupStage
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
        ++ lib.optional cfg.vaultwarden.enable vaultwardenBackupDir
        ++ lib.optionals cfg.ai.enable [
          "/var/lib/nas-llama-swap"
          "/var/lib/open-webui"
          "${aiStorageRoot}/downloader-config"
        ];
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
          ${lib.optionalString cfg.vaultwarden.enable ''systemctl start backup-vaultwarden.service''}

          # Capture PostgreSQL consistently instead of copying its live data directory.
          ${pkgs.util-linux}/bin/runuser -u postgres -- \
            ${config.services.postgresql.package}/bin/pg_dump --format=custom authentik \
            > "$backup_stage/authentik.pgdump"
          chmod 0600 "$backup_stage/authentik.pgdump"

          # Stage only CopyParty databases; its state tree includes NAS data mounts.
          install -d -m 0700 "$backup_stage/copyparty"
          for name in shares.db sessions.db; do
            source=/var/lib/copyparty/copyparty/$name
            destination="$backup_stage/copyparty/$name"
            if [[ -f "$source" ]]; then
              # Use SQLite's online backup API and pass paths as argv, never as SQL text.
              ${pkgs.python3}/bin/python3 - "$source" "$destination" <<'PYSQLITEBACKUP'
import pathlib
import sqlite3
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as source_db:
    with sqlite3.connect(destination) as destination_db:
        source_db.backup(destination_db)
PYSQLITEBACKUP
              chmod 0600 "$destination"
            fi
          done

          ${lib.optionalString cfg.syncthing.enable ''
          install -d -m 0700 "$backup_stage/syncthing"
          for name in cert.pem key.pem config.xml; do
            if [[ -f ${syncthingConfigDir}/$name ]]; then
              install -m 0600 ${syncthingConfigDir}/$name "$backup_stage/syncthing/$name"
            fi
          done
          ''}
        '';
        backupCleanupCommand = ''
          #!${pkgs.runtimeShell}
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
      requires = lib.optional (cfg.backup.repositoryFile == "") "nas-zfs-mount-guard.service";
      after = lib.optional (cfg.backup.repositoryFile == "") "nas-zfs-mount-guard.service";
      unitConfig = {
        RequiresMountsFor = [ backupStage ] ++ lib.optional (cfg.backup.repositoryFile == "") cfg.zfsRoot;
        ConditionPathExists = cfg.backup.passwordFile;
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
      path = [
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.python3
        pkgs.sqlite
        pkgs.util-linux
        config.services.postgresql.package
      ];
      script = ''
        set -euo pipefail
        verify_root=${lib.escapeShellArg restoreVerifyPath}
        restore_root="$verify_root/restored"
        pgdata="$verify_root/postgresql"
        pgsocket="$verify_root/socket"
        cleanup() {
          if [[ -f "$pgdata/postmaster.pid" ]]; then
            ${pkgs.util-linux}/bin/runuser -u postgres -- \
              ${config.services.postgresql.package}/bin/pg_ctl \
              -D "$pgdata" -m immediate stop >/dev/null 2>&1 || true
          fi
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

        staged="$restore_root${backupStage}"
        [[ -s "$staged/authentik.pgdump" ]]
        install -d -m 0700 -o postgres -g postgres "$pgdata" "$pgsocket"
        ${pkgs.util-linux}/bin/runuser -u postgres -- \
          ${config.services.postgresql.package}/bin/initdb \
          -D "$pgdata" --auth=trust --no-locale >/dev/null
        ${pkgs.util-linux}/bin/runuser -u postgres -- \
          ${config.services.postgresql.package}/bin/pg_ctl \
          -D "$pgdata" -o "-k $pgsocket -p 55432 -c listen_addresses=\"\"" \
          -w start >/dev/null
        ${pkgs.util-linux}/bin/runuser -u postgres -- \
          ${config.services.postgresql.package}/bin/createdb \
          -h "$pgsocket" -p 55432 authentik_verify
        ${pkgs.util-linux}/bin/runuser -u postgres -- \
          ${config.services.postgresql.package}/bin/pg_restore \
          -h "$pgsocket" -p 55432 --no-owner \
          --dbname=authentik_verify "$staged/authentik.pgdump"
        ${pkgs.util-linux}/bin/runuser -u postgres -- \
          ${config.services.postgresql.package}/bin/psql \
          -h "$pgsocket" -p 55432 -d authentik_verify \
          -Atqc "SELECT count(*) > 0 FROM django_migrations" | grep -Fxq t
        ${pkgs.util-linux}/bin/runuser -u postgres -- \
          ${config.services.postgresql.package}/bin/psql \
          -h "$pgsocket" -p 55432 -d authentik_verify \
          -Atqc "SELECT to_regclass('public.authentik_core_user') IS NOT NULL" | grep -Fxq t

        for database in "$staged"/copyparty/*.db; do
          [[ -e "$database" ]] || continue
          [[ "$(${pkgs.sqlite}/bin/sqlite3 "$database" 'PRAGMA integrity_check;')" == ok ]]
        done
        ${lib.optionalString cfg.syncthing.enable ''
        ${pkgs.python3}/bin/python3 - "$staged/syncthing/config.xml" <<'PYXML'
import pathlib
import sys
import xml.etree.ElementTree as ET
path = pathlib.Path(sys.argv[1])
if path.exists():
    ET.parse(path)
PYXML
        ''}
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