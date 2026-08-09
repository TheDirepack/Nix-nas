{ lib, ... }:

{
  imports = [ ./vm-common.nix ];

  networking.usePredictableInterfaceNames = lib.mkForce false;
  nas.trustedInterfaces = lib.mkForce [ "eth0" ];
  users.users.admin.openssh.authorizedKeys.keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICITestFixtureOnlyKeyMaterial000000000000000 nas-ci"
  ];

  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_scsi"
    "9p"
    "9pnet_virtio"
  ];
  boot.loader.systemd-boot.enable = lib.mkForce false;
  boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
  boot.loader.grub = {
    enable = lib.mkForce true;
    device = lib.mkForce "/dev/vda";
  };

  fileSystems."/" = {
    device = "/dev/disk/by-label/NIXOS_QEMU_ROOT";
    fsType = "ext4";
  };
  swapDevices = [ ];
}
