{ pkgs, self, copyparty }:

let
  timeoutBudget = builtins.fromJSON (builtins.readFile ../vm/timeout-budget.json);
  outerKillAfter = timeoutBudget.timeouts.killAfter;
  phaseBudget = phase:
    phase.fixedSeconds
    + phase.ordinaryWaits * timeoutBudget.ordinaryWaitSeconds
    + pkgs.lib.foldl' (total: key: total + (builtins.getAttr key timeoutBudget.timeouts)) 0 phase.timeoutKeys;
  guestWatchdog = pkgs.lib.foldl' (total: phase: total + phaseBudget phase) 0 timeoutBudget.phases
    + timeoutBudget.slackSeconds;
  deviceAllowProbe = pkgs.writeText "nas-vm-device-allow.py" ''
    import errno
    import json
    import os
    import pathlib
    import stat
    import subprocess
    import sys
    import tempfile

    sys.path.insert(0, "${../../services}")
    from nas_v2_systemd_attachments import attachment_lines

    subprocess.run(["systemctl", "--version"], check=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="nas-deviceallow-", dir="/run") as temporary:
        root = pathlib.Path(temporary)
        for index, device in enumerate(("/dev/nas-deviceallow-probe", "/dev/nas-deviceallow probe")):
            node = pathlib.Path(device)
            os.mknod(node, stat.S_IFCHR | 0o600, os.makedev(1, 3))
            try:
                projected = attachment_lines({}, {
                    "runtime": {"type": "systemd"},
                    "resources": {"accelerators": [{"mode": "shared", "device": device}]},
                })
                legacy = [line.replace('" rw', ' rw"') if line.startswith("DeviceAllow=") else line for line in projected]
                for variant, lines, expected in (("denied", [], False), ("legacy", legacy, False), ("projected", projected, True)):
                    name = f"nas-vm-deviceallow-{index}-{variant}.service"
                    unit = pathlib.Path("/run/systemd/system") / name
                    report = root / f"{index}-{variant}.json"
                    probe = root / f"{index}-{variant}.py"
                    probe.write_text(
                        "import errno,json,os,pathlib\nresult={}\n"
                        "for name,mode in [('read',os.O_RDONLY),('write',os.O_WRONLY)]:\n"
                        " try:\n"
                        f"  fd=os.open({device!r},mode);os.close(fd);result[name]=True\n"
                        " except OSError as error:\n"
                        "  if error.errno not in (errno.EPERM,errno.EACCES):raise\n"
                        "  result[name]=False\n"
                        f"pathlib.Path({str(report)!r}).write_text(json.dumps(result))\n"
                    )
                    # /dev/null is always available for stdio even under DevicePolicy=strict;
                    # it is not the device under test and does not weaken enforcement.
                    stdio_allow = ["DeviceAllow=/dev/null rw"]
                    unit.write_text("\n".join([
                        "[Service]", "Type=oneshot", *stdio_allow, *lines,
                        # Strict mode removes systemd's implicit pseudo-device grants,
                        # making this harmless /dev/null alias an enforcement probe.
                        "DevicePolicy=strict", f"ExecStart=${pkgs.python3}/bin/python {probe}", "",
                    ]))
                    try:
                        subprocess.run(["systemctl", "daemon-reload"], check=True)
                        subprocess.run(["systemctl", "start", name], check=True)
                        parsed = subprocess.check_output(["systemctl", "show", name, "-p", "DeviceAllow", "--value"], text=True)
                        observed = json.loads(report.read_text())
                        results.append({"device": device, "variant": variant, "parsed": parsed, "observed": observed})
                        print(json.dumps(results[-1]), flush=True)
                        assert observed == {"read": expected, "write": expected}, results[-1]
                    finally:
                        subprocess.run(["systemctl", "stop", name], check=True)
                        unit.unlink()
                        subprocess.run(["systemctl", "daemon-reload"], check=True)
            finally:
                node.unlink()
    assert len(results) == 6
  '';
in

pkgs.testers.runNixOSTest {
  name = "nixos-nas-full-stack";
  globalTimeout = 2 * 60 * 60;

  nodes.machine = { ... }: {
    imports = [
      copyparty.nixosModules.default
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
    machine.succeed("busctl --system call org.freedesktop.UDisks2 /org/freedesktop/UDisks2 org.freedesktop.DBus.ObjectManager GetManagedObjects >/dev/null")
    machine.succeed("test $(systemctl show -p Result --value nas-vm-test-repository.service) = success")
    machine.succeed("${pkgs.python3}/bin/python ${deviceAllowProbe}")
    machine.succeed("test ! -e /run/nas-secret-runtime/live/ready")
    machine.succeed("systemctl start nas-managed-services-reconcile.service")
    machine.succeed("test $(systemctl show -p ConditionResult --value nas-managed-services-reconcile.service) = no")
    machine.succeed("test ! -e /run/nas-control/systemd-reconciled.json")
    machine.succeed("! systemctl is-active --quiet copyparty.service")
    machine.succeed("test ! -e /run/nas-control/rollback-guard/current-guard-unit")
    machine.succeed("systemctl start nas-v2-apply-failed.service")
    machine.succeed("test $(systemctl show -p ConditionResult --value nas-v2-apply-failed.service) = no")
    machine.succeed("! systemctl is-failed --quiet nas-v2-apply-failed.service")
    machine.succeed("systemctl restart firewalld.service nas-firewall-baseline.service")
    machine.succeed("systemctl is-active --quiet nas-firewall-baseline.service")
    machine.succeed("firewall-cmd --state")
    machine.succeed("timeout --verbose --signal=TERM --kill-after=${toString outerKillAfter}s ${toString guestWatchdog}s nas-vm-guest-test /dev/vdb")
    machine.succeed("test $(zfs get -H -o value encryption tank/nas) = off")
    machine.succeed("timeout --signal=TERM --kill-after=${toString outerKillAfter}s ${toString timeoutBudget.timeouts.secretAdversarial}s nas-vm-secret-adversarial")
    machine.succeed("NAS_INSTALLED_FUZZ_SMOKE=1 timeout --signal=TERM --kill-after=${toString outerKillAfter}s ${toString timeoutBudget.timeouts.installedSmoke}s python3 /var/lib/nas-test/repo/tests/vm/adversarial-installed.py >/tmp/nas-installed-command-smoke.json")
    machine.succeed("jq -e '.ok == true and .smoke == true and .commands > 0' /tmp/nas-installed-command-smoke.json >/dev/null")
  '';
}
