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
    machine.wait_for_unit("nas-vm-test-repository.service")
    machine.succeed("timeout 1800 nas-vm-guest-test /dev/vdb")
    machine.succeed("timeout 900 nas-vm-secret-adversarial")
  '';
}
