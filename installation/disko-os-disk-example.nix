# Destructive example: replace the OS device ID and review generated commands before use.
{
  disko.devices.disk.os = {
    type = "disk";
    device = "/dev/disk/by-id/REPLACE_WITH_OS_DISK_ID";
    content = {
      type = "gpt";
      partitions = {
        ESP = {
          type = "EF00";
          size = "1G";
          content = {
            type = "filesystem";
            format = "vfat";
            mountpoint = "/boot";
            mountOptions = [ "umask=0077" ];
          };
        };
        root = {
          size = "100%";
          content = {
            type = "filesystem";
            format = "ext4";
            mountpoint = "/";
          };
        };
      };
    };
  };
}
