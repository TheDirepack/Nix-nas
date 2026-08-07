{ lib, ... }:

{
  options.nas = {
    virtualization = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable hardware-accelerated QEMU/KVM managed by libvirt and Cockpit Machines.";
      };
      storagePath = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Directory for VM disk images. Empty defaults to nas.zfsRoot/virtual-machines.";
      };
      runAsRoot = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Run QEMU guests as root. Keep false unless passthrough requirements make it unavoidable.";
      };
      swtpm = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable software TPM support for modern guest operating systems.";
      };
      virtiofs = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Install virtiofsd for efficient host-to-guest shared directories.";
      };
      allowedBridges = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Host bridge interfaces permitted for libvirt session networking.";
      };
    };
  };
}
