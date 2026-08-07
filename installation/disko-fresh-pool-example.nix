# Destructive example: replace every device ID and review generated commands before use.
{
  disko.devices = {
    disk = {
      data0 = {
        type = "disk";
        device = "/dev/disk/by-id/REPLACE_WITH_DATA_DISK_0";
        content = {
          type = "gpt";
          partitions.zfs = {
            size = "100%";
            content = { type = "zfs"; pool = "tank"; };
          };
        };
      };
      data1 = {
        type = "disk";
        device = "/dev/disk/by-id/REPLACE_WITH_DATA_DISK_1";
        content = {
          type = "gpt";
          partitions.zfs = {
            size = "100%";
            content = { type = "zfs"; pool = "tank"; };
          };
        };
      };
    };

    zpool.tank = {
      type = "zpool";
      mode = "mirror";
      options.ashift = "12";
      rootFsOptions = {
        compression = "zstd";
        atime = "off";
        xattr = "sa";
        acltype = "posixacl";
        mountpoint = "none";
      };
      datasets.nas = {
        type = "zfs_fs";
        mountpoint = "/tank";
      };
    };
  };
}
