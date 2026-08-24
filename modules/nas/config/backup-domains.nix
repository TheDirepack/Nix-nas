{ config, lib, pkgs, nasInternal, ... }:

let
  cfg = config.nas;
  rootControlArtifactDir = "/var/lib/nas-backup/root-control";
  rootControlDatabaseDump = "${rootControlArtifactDir}/authentik.pgdump";
  restoreVerifyPath = cfg.backup.restoreVerification.targetPath;
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
  hasUserSendOptions = lib.any (
    argument: lib.hasPrefix "--sendoptions" argument
  ) cfg.zfsReplication.extraArgs;
in
{
  config = lib.mkMerge [
    # Restic is deliberately the root/control-plane backup domain. The ZFS data
    # domain is replicated natively below, so Restic must never traverse the ZFS
    # mount or consume V2 per-application backup inventories.
    (lib.mkIf cfg.backup.enable {
      services.restic.backups.nas-boot-system = {
        paths = lib.mkForce [
          "/"
          "/boot"
        ];
        dynamicFilesFrom = lib.mkForce null;
        exclude = lib.mkForce (
          [
            "/dev"
            "/proc"
            "/sys"
            "/run"
            "/tmp"
            "/var/tmp"
            "/var/cache"
            "/var/lib/postgresql"
            restoreVerifyPath
            cfg.zfsRoot
          ]
          ++ localRepositoryExclude
        );
        extraBackupArgs = lib.mkAfter [
          "--one-file-system"
          "--tag=root-control-plane"
        ];
        backupPrepareCommand = lib.mkForce ''
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
        backupCleanupCommand = lib.mkForce ''
          #!${pkgs.runtimeShell}
          set -euo pipefail
          rm -f -- ${lib.escapeShellArg rootControlDatabaseDump}
        '';
      };

      systemd.services.nas-backup-restore-verify = lib.mkIf cfg.backup.restoreVerification.enable {
        script = lib.mkForce ''
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

          # The root recovery snapshot may contain the /var/lib/nas-control
          # symlink itself, but it must never contain a copied mutable V2 authority
          # from the encrypted ZFS filesystem.
          if [[ -f "$restore_root${cfg.zfsRoot}/nas-control/services.yaml" ]]; then
            echo "Root Restic backup unexpectedly contains the ZFS V2 desired-state authority" >&2
            exit 1
          fi
        '';
        path = lib.mkAfter [ config.services.postgresql.package pkgs.restic ];
      };
    })

    # Native encrypted replication is the complete ZFS backup domain. Syncoid
    # forwards this to `zfs send`; raw sends preserve the source ciphertext and
    # avoid creating any plaintext archive or application-specific backup path.
    (lib.mkIf (cfg.zfsReplication.enable && cfg.zfsEncryption.enable) {
      assertions = [
        {
          assertion = !hasUserSendOptions;
          message = "Encrypted NAS ZFS replication reserves Syncoid --sendoptions so raw -w sends cannot be overridden.";
        }
      ];
      nas.zfsReplication.extraArgs = lib.mkBefore [ "--sendoptions=w" ];
    })
  ];
}
