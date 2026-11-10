{ lib, ... }:

let
  retiredRemote = [ "nas" "backup" "remote" ];
  remoteMigration = ''
    Restic reads rclone and every other backend natively through
    nas.backup.repositoryFile. Write the repository (for example
    rclone:gdrive:nas-backup; the retired provider default was
    rclone:<rcloneRemote>, or rclone:<provider>:nas-backup when rcloneRemote
    was empty) to a root-owned 0600 file and set nas.backup.repositoryFile to
    that file.
  '';
in
{
  imports = [
    (lib.mkRemovedOptionModule (retiredRemote ++ [ "enable" ]) remoteMigration)
    (lib.mkRemovedOptionModule (retiredRemote ++ [ "provider" ]) remoteMigration)
    (lib.mkRemovedOptionModule (retiredRemote ++ [ "rcloneRemote" ]) remoteMigration)
    (lib.mkRemovedOptionModule (retiredRemote ++ [ "scope" ]) ''
      It never limited what was backed up: nas-boot-system always backs up its
      complete profile to the configured repository. Remove the setting.
    '')
    (lib.mkRenamedOptionModule (retiredRemote ++ [ "rcloneConfigFile" ]) [ "nas" "backup" "rcloneConfigFile" ])
  ];

  options.nas = {
    alerting.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Continuously evaluate VictoriaMetrics rules with vmalert and deliver notifications through the hardened NAS alert router and optional native ntfy server.";
    };

    backup = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable Restic recovery backups for the boot filesystem, appliance configuration, and mutable service state.";
      };
      localRepository = lib.mkOption {
        type = lib.types.str;
        default = "";
        example = "/tank/backups/restic-system";
        description = ''
          Local Restic repository used when repositoryFile is empty. An empty
          value selects <nas.zfsRoot>/backups/restic-system. This protects the
          boot device and is replicated with the ZFS dataset when Syncoid is
          enabled; by itself, a repository on the same pool is not protection
          against whole-pool loss.
        '';
      };
      repositoryFile = lib.mkOption {
        type = lib.types.str;
        default = "";
        example = "/run/secrets/restic-repository";
        description = ''
          Private file containing the Restic repository (Restic --repository-file).
          This is the only way to configure an off-pool repository, including any
          Restic backend such as sftp:, rest:, s3:, b2: or rclone:<remote>:<path>.
          When set, it overrides localRepository. nas-backup-status rejects a file
          that names a path on the managed pool as an independent repository.
        '';
      };
      rcloneConfigFile = lib.mkOption {
        type = lib.types.str;
        default = "";
        example = "/run/secrets/rclone.conf";
        description = "Private rclone.conf used when nas.backup.repositoryFile names an rclone: repository. Empty uses rclone's default configuration location.";
      };
      passwordFile = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Secret file containing the Restic repository password.";
      };
      allowSamePoolRepository = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Explicitly permit a local rollback-only Restic repository on the managed ZFS pool.";
      };
      stagingPath = lib.mkOption {
        type = lib.types.strMatching "^/.*";
        default = "/var/lib/nas-backup/staging";
        description = "Disk-backed private directory used for consistent database snapshots before Restic runs.";
      };
      stagingMinFreeBytes = lib.mkOption {
        type = lib.types.ints.positive;
        default = 1073741824;
        description = "Minimum free bytes required on the backup staging filesystem before snapshot preparation.";
      };
      restoreVerification = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Periodically restore the latest backup into isolated scratch storage and validate PostgreSQL, SQLite, XML, and required state files.";
        };
        onCalendar = lib.mkOption {
          type = lib.types.str;
          default = "monthly";
          description = "systemd calendar expression for isolated backup restore verification.";
        };
        targetPath = lib.mkOption {
          type = lib.types.strMatching "^/.*";
          default = "/var/lib/nas-backup/restore-verify";
          description = "Disk-backed scratch directory used only for isolated restore verification.";
        };
      };
    };

    autoUpdate = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Schedule the guarded nas-update check/build workflow. This does not activate an update unless nas.autoUpdate.apply is also true.";
      };
      onCalendar = lib.mkOption {
        type = lib.types.str;
        default = "Mon 03:00";
        description = "systemd calendar expression for automatic update checks/builds.";
      };
      apply = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Automatically activate the exact reviewed checkout after successful build and health checks. When false, scheduled runs validate/fetch/build only and leave the active system unchanged. Requires nas.update.externalProbeCommand.";
      };
    };

    update.externalProbeCommand = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = lib.literalExpression ''[ "''${pkgs.openssh}/bin/ssh" "-o" "BatchMode=yes" "probe@monitor.lan" "check-nas-reachability" ]'';
      description = ''
        Independent management reachability probe that nas-update runs, as an
        argument vector without a shell, after a candidate generation passes
        local health checks and again after it becomes persistent. A nonzero
        exit rolls the update back. The command must confirm that the NAS
        management path is reachable from outside this host, for example by
        asking a second machine to load the NAS sign-in page.

        The first element must be an absolute executable path. Arguments are
        stored in the Nix store and the process environment, so they must not
        contain credentials; let the probe read secrets from its own private file.

        While this is empty, persistent deployment is unavailable: Cockpit
        disables Apply, nas-update --apply refuses before building, and
        nas.autoUpdate.apply cannot be enabled. Only an administrator on the
        recovery plane may use nas-update --apply --allow-local-health-only.
      '';
    };
  };
}
