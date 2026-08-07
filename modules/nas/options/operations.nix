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
