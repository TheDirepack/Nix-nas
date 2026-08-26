{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  rootControlArtifactDir = "/var/lib/nas-backup/root-control";
  rootControlDatabaseDump = "${rootControlArtifactDir}/authentik.pgdump";
  restoreVerifyPath = cfg.backup.restoreVerification.targetPath;
  safeRestoreVerifyPath =
    lib.hasPrefix "/var/lib/nas-backup/" restoreVerifyPath
    && restoreVerifyPath != "/var/lib/nas-backup/"
    && restoreVerifyPath != rootControlArtifactDir
    && !lib.hasInfix "/../" restoreVerifyPath
    && !lib.hasSuffix "/.." restoreVerifyPath
    && !lib.hasInfix "/./" restoreVerifyPath
    && !lib.hasPrefix "${rootControlArtifactDir}/" restoreVerifyPath
    && !lib.hasPrefix "${restoreVerifyPath}/" rootControlArtifactDir;
  localResticRepository =
    if cfg.backup.localRepository != "" then cfg.backup.localRepository
    else "${cfg.zfsRoot}/backups/restic-system";
  remoteEnabled = cfg.backup.remote.enable && cfg.backup.remote.provider != "local";
  derivedRcloneRemote =
    if cfg.backup.remote.rcloneRemote != "" then cfg.backup.remote.rcloneRemote
    else if cfg.backup.remote.provider == "gdrive" then "gdrive:nas-backup"
    else if cfg.backup.remote.provider == "pcloud" then "pcloud:nas-backup"
    else if cfg.backup.remote.provider == "s3" then "s3:nas-backup"
    else if cfg.backup.remote.provider == "b2" then "b2:nas-backup"
    else if cfg.backup.remote.provider == "icloud" then "icloud:nas-backup"
    else "rclone:nas-backup";
  effectiveRepository =
    if cfg.backup.repositoryFile != "" then null
    else if remoteEnabled then "rclone:${derivedRcloneRemote}"
    else localResticRepository;
  repositoryArgs =
    if cfg.backup.repositoryFile != ""
    then [ "--repository-file" cfg.backup.repositoryFile ]
    else [ "--repo" effectiveRepository ];
  resticCommand = "${pkgs.restic}/bin/restic ${lib.escapeShellArgs repositoryArgs}";
  localRepositoryExclude = lib.optional (
    cfg.backup.repositoryFile == ""
    && !remoteEnabled
    && lib.hasPrefix "/" localResticRepository
  ) localResticRepository;
  samePoolRepository =
    cfg.backup.repositoryFile == ""
    && !remoteEnabled
    && (
      localResticRepository == cfg.zfsRoot
      || lib.hasPrefix "${cfg.zfsRoot}/" localResticRepository
    );
  reviewedSyncoidArgs =
    lib.optional cfg.zfsReplication.recursive "--recursive"
    ++ lib.optional cfg.zfsReplication.useExistingSnapshots "--no-sync-snap"
    ++ lib.filter (argument: !(lib.hasPrefix "--sendoptions" argument)) cfg.zfsReplication.extraArgs
    ++ lib.optional cfg.zfsEncryption.enable "--sendoptions=w"
    ++ [ cfg.zfsDataset cfg.zfsReplication.target ];
in
{
  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !cfg.backup.enable || !samePoolRepository || cfg.backup.allowSamePoolRepository;
          message = ''
            nas.backup root/control-plane recovery must be stored independently of
            the encrypted ZFS source. Configure an external repository/remote, or
            set nas.backup.allowSamePoolRepository only for a rollback-only copy
            that is not considered bare-metal recovery protection.
          '';
        }
        {
          assertion = !cfg.backup.enable || !cfg.backup.restoreVerification.enable || safeRestoreVerifyPath;
          message = ''
            nas.backup.restoreVerification.targetPath is deleted recursively during
            verification and must therefore be a dedicated child of
            /var/lib/nas-backup/, without dot-dot traversal and separate from the
            root-control backup artifact directory.
          '';
        }
        {
          assertion = !cfg.zfsReplication.enable || cfg.zfsEncryption.enable;
          message = ''
            nas.zfsReplication is the complete encrypted ZFS backup domain and
            therefore requires nas.zfsEncryption.enable so Syncoid can preserve
            the source encryption with a raw send.
          '';
        }
      ];
    }

    (lib.mkIf cfg.backup.enable {
      services.restic.backups.nas-boot-system = {
        paths = lib.mkOverride 40 [
          "/"
          "/boot"
        ];
        dynamicFilesFrom = lib.mkOverride 40 null;
        exclude = lib.mkOverride 40 (
          [
            "/dev"
            "/proc"
            "/sys"
            "/run"
            "/tmp"
            "/var/tmp"
            "/var/cache"
            "/var/lib/postgresql"
            "/var/lib/nas-operational/postgresql"
            restoreVerifyPath
            cfg.zfsRoot
          ]
          ++ localRepositoryExclude
        );
        extraBackupArgs = lib.mkAfter [
          "--one-file-system"
          "--tag=root-control-plane"
        ];
        backupPrepareCommand = lib.mkOverride 40 ''
          #!${pkgs.runtimeShell}
          set -euo pipefail
          artifact_dir=${lib.escapeShellArg rootControlArtifactDir}
          dump=${lib.escapeShellArg rootControlDatabaseDump}
          install -d -m 0700 "$artifact_dir"
          tmp="$(mktemp "$artifact_dir/.authentik.pgdump.XXXXXX")"
          cleanup() { rm -f -- "$tmp"; }
          trap cleanup EXIT
          ${pkgs.util-linux}/bin/runuser -u postgres -- \
            ${config.services.postgresql.package}/bin/pg_dump --format=custom authentik > "$tmp"
          chmod 0600 "$tmp"
          mv -f "$tmp" "$dump"
          trap - EXIT
          ${lib.optionalString (cfg.backup.repositoryFile == "" && !remoteEnabled) ''
          install -d -m 0700 ${lib.escapeShellArg localResticRepository}
          ''}
        '';
        backupCleanupCommand = lib.mkOverride 40 ''
          #!${pkgs.runtimeShell}
          set -euo pipefail
          rm -f -- ${lib.escapeShellArg rootControlDatabaseDump}
        '';
      };

      systemd.services.nas-backup-restore-verify = lib.mkIf cfg.backup.restoreVerification.enable {
        script = lib.mkOverride 40 ''
          set -euo pipefail
          verify_root=${lib.escapeShellArg restoreVerifyPath}
          restore_root="$verify_root/restored"
          cleanup() { rm -rf -- "$verify_root"; }
          trap cleanup EXIT
          rm -rf -- "$verify_root"
          install -d -m 0711 "$verify_root"
          install -d -m 0700 "$restore_root"
          available=$(${pkgs.coreutils}/bin/df --output=avail -B1 "$verify_root" | ${pkgs.coreutils}/bin/tail -n 1 | ${pkgs.coreutils}/bin/tr -d "[:space:]")
          [[ "$available" =~ ^[0-9]+$ && "$available" -ge ${toString cfg.backup.stagingMinFreeBytes} ]] || {
            echo "Insufficient free space in $verify_root" >&2
            exit 1
          }
          export RESTIC_PASSWORD_FILE=${lib.escapeShellArg cfg.backup.passwordFile}
          ${resticCommand} restore latest --tag root-control-plane --target "$restore_root"

          [[ -s "$restore_root${cfg.secrets.keepassDatabase}" ]]
          [[ -s "$restore_root${rootControlDatabaseDump}" ]]
          ${config.services.postgresql.package}/bin/pg_restore --list \
            "$restore_root${rootControlDatabaseDump}" >/dev/null
          [[ -d "$restore_root/var/lib/authentik" ]]
          [[ -d "$restore_root/etc" ]]

          if [[ -f "$restore_root${cfg.zfsRoot}/nas-control/services.yaml" ]]; then
            echo "Root Restic backup unexpectedly contains the ZFS V2 desired-state authority" >&2
            exit 1
          fi
        '';
        path = lib.mkAfter [ config.services.postgresql.package pkgs.restic ];
      };
    })

    (lib.mkIf cfg.zfsReplication.enable {
      systemd.services.nas-syncoid.serviceConfig.ExecStart = lib.mkOverride 40 (
        "${pkgs.sanoid}/bin/syncoid ${lib.escapeShellArgs reviewedSyncoidArgs}"
      );
    })
  ];
}