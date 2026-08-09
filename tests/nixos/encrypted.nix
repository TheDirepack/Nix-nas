{ pkgs, self, copyparty }:

pkgs.testers.runNixOSTest {
  name = "nixos-nas-encrypted-zfs";

  nodes.machine = { lib, ... }: {
    imports = [
      copyparty.nixosModules.default
      self.nixosModules.ai
      self.nixosModules.core
      ../../local.nix
      ./vm-common.nix
    ];

    nas.zfsEncryption.enable = lib.mkForce true;
    nas.trustedInterfaces = lib.mkForce [ "eth1" ];
    nas.testing.readOnlyPackageSet = true;
    users.users.admin.openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICITestFixtureOnlyKeyMaterial000000000000000 nas-ci"
    ];
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
    machine.succeed("test $(systemctl show -p Result --value nas-vm-test-repository.service) = success")
    machine.succeed("timeout 1800 nas-vm-encrypted-guest-test /dev/vdb")
  '';
}
