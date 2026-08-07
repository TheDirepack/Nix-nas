{ ... }:

{
  boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" ];
  fileSystems."/" = {
    device = "/dev/disk/by-label/NIXOS_CI_ROOT";
    fsType = "ext4";
  };
  fileSystems."/boot" = {
    device = "/dev/disk/by-label/NIXOS_CI_BOOT";
    fsType = "vfat";
  };
}
