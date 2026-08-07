{ lib, ... }:

{
  options.nas = {
    zfsRoot = lib.mkOption {
      type = lib.types.strMatching "^/[^[:space:]]*$";
      default = "/tank";
      description = "Mount point of the dedicated ZFS dataset containing NAS shares.";
    };
    zfsPool = lib.mkOption {
      type = lib.types.strMatching "^[A-Za-z0-9][A-Za-z0-9_.:-]*$";
      default = "tank";
      description = "ZFS pool imported for the NAS.";
    };
    zfsDataset = lib.mkOption {
      type = lib.types.strMatching "^[A-Za-z0-9][A-Za-z0-9_.:-]*(/[A-Za-z0-9][A-Za-z0-9_.:-]*)+$";
      default = "tank/nas";
      description = "Child ZFS dataset recursively managed by Sanoid and mounted at nas.zfsRoot.";
    };
    zfsImportAtBoot = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Import nas.zfsPool at boot after the pool has been created and verified.";
    };
    zfsTrimEnable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable scheduled zpool trim only when every relevant pool device supports TRIM.";
    };
    zfsEncryption = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Unlock nas.zfsDataset with a ZFS native-encryption key stored in the configured KeePassXC database.";
      };
      algorithm = lib.mkOption {
        type = lib.types.enum [ "aes-256-gcm" "aes-192-gcm" "aes-128-gcm" ];
        default = "aes-256-gcm";
        description = "ZFS native-encryption algorithm used when creating the managed encryption root.";
      };
    };
    zfsReplication = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Replicate nas.zfsDataset and its child datasets with Syncoid.";
      };
      target = lib.mkOption {
        type = lib.types.strMatching "^$|^[^-[:space:]][^[:space:]]*$";
        default = "";
        example = "backup@backup-nas:tank/replicas/nas";
        description = "Syncoid destination dataset, either local or [[user@]host:]dataset.";
      };
      recursive = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Replicate child datasets recursively.";
      };
      useExistingSnapshots = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Transfer Sanoid-created snapshots without creating an additional Syncoid snapshot.";
      };
      onCalendar = lib.mkOption {
        type = lib.types.str;
        default = "daily";
        description = "systemd calendar expression for ZFS replication.";
      };
      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "--compress=zstd-fast" "--source-bwlimit=100m" ];
        description = "Additional reviewed Syncoid arguments. Source and target are appended automatically.";
      };
    };
    webdav.adminEnable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable use of the CopyParty admin credential over direct WebDAV. Disabled by default because protocol login cannot enforce browser MFA.";
    };
  };
}
