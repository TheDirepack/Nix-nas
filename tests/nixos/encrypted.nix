{ pkgs, self, copyparty }:

pkgs.testers.runNixOSTest {
  name = "nixos-nas-encrypted-zfs";

  nodes.machine = { lib, ... }: {
    imports = [
      self.nixosModules.default
      ../../local.nix
      ./vm-common.nix
    ];

    nas.zfsEncryption.enable = lib.mkForce true;
    nas.trustedInterfaces = lib.mkForce [ "eth1" ];
    boot.loader.systemd-boot.enable = lib.mkForce true;
    boot.loader.efi.canTouchEfiVariables = lib.mkForce false;

    virtualisation = {
      memorySize = 8192;
      cores = 4;
      diskSize = 24576;
      emptyDiskImages = [ 8192 ];
      qemu.options = [ "-device" "virtio-rng-pci" ];
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("nas-vm-test-repository.service")
    machine.succeed("timeout 1800 nas-vm-encrypted-guest-test /dev/vdb")
  '';
}
