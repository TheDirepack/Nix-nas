{ pkgs, self, copyparty }:

let
  timeoutBudget = builtins.fromJSON (builtins.readFile ../vm/timeout-budget.json);
  phaseBudget = phase:
    phase.fixedSeconds
    + phase.ordinaryWaits * timeoutBudget.ordinaryWaitSeconds
    + pkgs.lib.foldl' (total: key: total + (builtins.getAttr key timeoutBudget.timeouts)) 0 phase.timeoutKeys;
  guestWatchdog = pkgs.lib.foldl' (total: phase: total + phaseBudget phase) 0 timeoutBudget.phases
    + timeoutBudget.slackSeconds;
in

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
    machine.succeed("timeout --verbose --kill-after=30s ${toString guestWatchdog}s nas-vm-guest-test /dev/vdb")
    machine.succeed("timeout ${toString timeoutBudget.timeouts.secretAdversarial} nas-vm-secret-adversarial")
    machine.succeed("NAS_INSTALLED_FUZZ_SMOKE=1 timeout ${toString timeoutBudget.timeouts.installedSmoke} python3 /var/lib/nas-test/repo/tests/vm/adversarial-installed.py >/tmp/nas-installed-command-smoke.json")
    machine.succeed("jq -e '.ok == true and .smoke == true and .commands > 0' /tmp/nas-installed-command-smoke.json >/dev/null")
  '';
}
