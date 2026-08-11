{ pkgs, self, copyparty }:

pkgs.testers.runNixOSTest {
  name = "nixos-nas-full-stack";

  nodes.machine = { ... }: {
    imports = [
      copyparty.nixosModules.default
      self.nixosModules.ai
      self.nixosModules.core
      ../../local.nix
      ./vm-common.nix
    ];

    nas.trustedInterfaces = pkgs.lib.mkForce [ "eth1" ];
    nas.testing.readOnlyPackageSet = true;
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
    # guest-test.sh is a complete-system qualification suite, not one operation.
    # Its bounded child stages include a 20-minute first-run, a 10-minute secret
    # activation, a 5-minute browser flow, and many 5-minute service waits.  The
    # old 30-minute aggregate watchdog could therefore kill healthy serialized
    # work before those child budgets were exhausted.  Keep a hard outer guard,
    # but give the complete suite a budget consistent with its internal bounds.
    machine.succeed("timeout --verbose --kill-after=30s 3600s nas-vm-guest-test /dev/vdb")
    machine.succeed("timeout 900 nas-vm-secret-adversarial")
    machine.succeed("NAS_INSTALLED_FUZZ_SMOKE=1 timeout 300 python3 /var/lib/nas-test/repo/tests/vm/adversarial-installed.py >/tmp/nas-installed-command-smoke.json")
    machine.succeed("jq -e '.ok == true and .smoke == true and .commands > 0' /tmp/nas-installed-command-smoke.json >/dev/null")
  '';
}
