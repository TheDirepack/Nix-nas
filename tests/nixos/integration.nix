{ pkgs, self, copyparty }:

pkgs.testers.runNixOSTest {
  name = "nixos-nas-full-stack";

  nodes.machine = { ... }: {
    imports = [
      self.nixosModules.default
      ../../local.nix
      ./vm-common.nix
    ];

    nas.trustedInterfaces = pkgs.lib.mkForce [ "eth1" ];
    users.users.admin.openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICITestFixtureOnlyKeyMaterial000000000000000 nas-ci"
    ];

    boot.loader.systemd-boot.enable = pkgs.lib.mkForce true;
    boot.loader.efi.canTouchEfiVariables = pkgs.lib.mkForce false;

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
    machine.succeed("timeout 1800 nas-vm-guest-test /dev/vdb")
    machine.succeed("timeout 900 nas-vm-secret-adversarial")
  '';
}
