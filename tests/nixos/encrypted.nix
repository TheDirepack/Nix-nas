{ pkgs, self, copyparty }:

let
  timeoutBudget = builtins.fromJSON (builtins.readFile ../vm/timeout-budget.json);
  outerKillAfter = timeoutBudget.timeouts.killAfter;
in

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
    # The shared VM fixture points the setup API at the full-stack first-run
    # document. This leg writes a distinct encrypted-storage plan, so keep the
    # API's review/submission contract aligned with the config under test.
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

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.succeed("test $(systemctl show -p Result --value nas-vm-test-repository.service) = success")
    machine.succeed("timeout --signal=TERM --kill-after=${toString outerKillAfter}s ${toString timeoutBudget.timeouts.encryptedGuest}s nas-vm-encrypted-guest-test /dev/vdb")
  '';
}
