{ pkgs, self, copyparty }:

let
  timeoutBudget = builtins.fromJSON (builtins.readFile ../vm/timeout-budget.json);
  outerKillAfter = timeoutBudget.timeouts.killAfter;
  encryptedNode = { lib, ... }: {
    imports = [
      copyparty.nixosModules.default
      self.nixosModules.core
      ../../local.nix
      ./vm-common.nix
    ];

    nas.zfsEncryption.enable = lib.mkForce true;
    # Both entrypoints must review and execute the same custom encrypted plan.
    nas.firstStart.configFile = lib.mkForce "/var/lib/nas-test/setup/encrypted-first-run.json";
    nas.trustedInterfaces = lib.mkForce [ "eth1" ];
    nas.testing.readOnlyPackageSet = true;
    users.users.admin.openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICITestFixtureOnlyKeyMaterial000000000000000 nas-ci"
    ];
    boot.loader.systemd-boot.enable = lib.mkForce true;
    boot.loader.efi.canTouchEfiVariables = lib.mkForce false;

    virtualisation = {
      memorySize = 4096;
      cores = 4;
      diskSize = 24576;
      emptyDiskImages = [ 8192 ];
      qemu.options = [ "-device" "virtio-rng-pci" ];
    };
  };
in

pkgs.testers.runNixOSTest {
  name = "nixos-nas-encrypted-zfs";

  nodes = {
    machine = encryptedNode;
    api = encryptedNode;
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.succeed("test $(systemctl show -p Result --value nas-vm-test-repository.service) = success")
    machine.succeed("timeout --signal=TERM --kill-after=${toString outerKillAfter}s ${toString timeoutBudget.timeouts.encryptedGuest}s nas-vm-encrypted-guest-test /dev/vdb")
    # Keep the two fresh encrypted guests within one VM's memory budget.
    machine.shutdown()
    api.wait_for_unit("multi-user.target")
    api.succeed("test $(systemctl show -p Result --value nas-vm-test-repository.service) = success")
    api.succeed("timeout --signal=TERM --kill-after=${toString outerKillAfter}s ${toString timeoutBudget.timeouts.encryptedGuest}s nas-vm-encrypted-guest-test /dev/vdb api")
  '';
}
