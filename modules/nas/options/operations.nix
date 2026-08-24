{ lib, ... }:

{
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
        description = "Enable the encrypted Restic recovery backup for the root/control-plane filesystem. ZFS application and user data is backed up separately by native ZFS replication.";
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
        description = "Optional secret file containing an external Restic repository URL. When set, it overrides localRepository.";
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
        description = "Disk-backed private directory available for backup scratch data.";
      };
      stagingMinFreeBytes = lib.mkOption {
        type = lib.types.ints.positive;
        default = 1073741824;
        description = "Minimum free bytes required on the backup verification/staging filesystem.";
      };
      restoreVerification = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Periodically restore the latest root/control-plane backup into isolated scratch storage and validate its recovery authorities.";
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
      remote = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable the root/control-plane Restic destination through rclone (Google Drive, iCloud, pCloud, S3, etc.).";
        };
        provider = lib.mkOption {
          type = lib.types.enum [ "local" "gdrive" "icloud" "pcloud" "s3" "b2" "rclone" ];
          default = "local";
          description = "Remote provider for restic+rclone. Use gdrive/icloud/pcloud/s3/b2/rclone; local keeps Restic at localRepository.";
        };
        rcloneRemote = lib.mkOption {
          type = lib.types.str;
          default = "";
          example = "gdrive:nas-backup";
          description = "Rclone remote target (e.g. gdrive:nas-backup, s3:bucket/prefix). Empty derives from provider.";
        };
        rcloneConfigFile = lib.mkOption {
          type = lib.types.str;
          default = "";
          description = "Absolute path to rclone.conf with credentials. Empty uses default location.";
        };
        rcloneExtraArgs = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Extra flags forwarded to rclone (e.g. --s3-no-check-bucket).";
        };
      };
    };

    autoUpdate = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Run the guarded nas-update workflow automatically.";
      };
      onCalendar = lib.mkOption {
        type = lib.types.str;
        default = "Mon 03:00";
        description = "systemd calendar expression for automatic updates.";
      };
      apply = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Activate the exact reviewed checkout after successful build and health checks. Keep false for validation-only runs.";
      };
    };
  };
}
