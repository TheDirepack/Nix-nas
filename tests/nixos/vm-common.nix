{ lib, pkgs, ... }:

let
  sourceTree = lib.cleanSourceWith {
    src = ../..;
    filter = path: _type:
      let name = builtins.baseNameOf path;
      in !(
        lib.elem name [ ".git" ".cache" ".pytest_cache" "__pycache__" "result" ]
        || lib.hasPrefix "result-" name
        || lib.hasSuffix ".pyc" name
      );
  };
  guestTest = pkgs.writeShellApplication {
    name = "nas-vm-guest-test";
    runtimeInputs = with pkgs; [
      bash
      caddy
      chromium
      chromedriver
      coreutils
      curl
      findutils
      git
      gnugrep
      iproute2
      jq
      keepassxc
      nodejs
      openssh
      (python3.withPackages (pythonPackages: [ pythonPackages.selenium ]))
      procps
      systemd
      util-linux
      zfs
    ];
    text = ''
      # Dedicated CI jobs have already qualified source tests, tooling, the
      # Cockpit production bundle, and Nix reference configurations before QEMU.
      # Keep nas-preflight exercised in the installed VM without recursively
      # rerunning those expensive owners during first-run and command smoke.
      export NAS_PREFLIGHT_SKIP_TESTS=1
      export NAS_PREFLIGHT_SKIP_TOOLING=1
      export NAS_PREFLIGHT_SKIP_NIX=1
      export NAS_PREFLIGHT_SKIP_COCKPIT_BUNDLE=1
      ${builtins.readFile ../vm/guest-test.sh}
    '';
  };
  secretAdversarialTest = pkgs.writeShellApplication {
    name = "nas-vm-secret-adversarial";
    runtimeInputs = with pkgs; [
      bash
      coreutils
      findutils
      gawk
      gnugrep
      keepassxc
      systemd
      util-linux
    ];
    text = builtins.readFile ../vm/secret-adversarial.sh;
  };
  reconfigureTest = pkgs.writeShellApplication {
    name = "nas-vm-reconfigure-test";
    runtimeInputs = with pkgs; [
      coreutils
      gnugrep
      python3
      systemd
    ];
    text = builtins.readFile ../vm/reconfigure-system.sh;
  };
  encryptedGuestTest = pkgs.writeShellApplication {
    name = "nas-vm-encrypted-guest-test";
    runtimeInputs = with pkgs; [
      bash
      coreutils
      gnugrep
      keepassxc
      procps
      systemd
      util-linux
      zfs
    ];
    text = builtins.readFile ../vm/encrypted-guest-test.sh;
  };
in
{
  networking.hostName = lib.mkForce "nas-test";
  networking.hostId = lib.mkForce "c1a05eed";
  networking.useDHCP = lib.mkDefault true;
  boot.supportedFilesystems = [ "zfs" ];

  users.users.admin.extraGroups = lib.mkAfter [ "wheel" ];
  security.sudo.wheelNeedsPassword = lib.mkForce false;

  services.openssh.settings = {
    PasswordAuthentication = lib.mkForce false;
    KbdInteractiveAuthentication = lib.mkForce false;
    PermitRootLogin = lib.mkForce "no";
  };

  nas = {
    installationReady = lib.mkForce true;
    testing.installationReadyFixture = true;
    configurationDir = lib.mkForce "/var/lib/nas-test/repo";
    adminPasswordHashFile = lib.mkForce (toString (pkgs.writeText "vm-admin-password-hash" "!"));
    zfsImportAtBoot = lib.mkForce false;
    zfsEncryption.enable = lib.mkDefault false;
    autoUpdate.enable = lib.mkForce false;
    backup.enable = lib.mkForce false;
    virtualization.enable = lib.mkForce false;
    tftp.enable = lib.mkForce true;
    alerting.enable = lib.mkForce true;
    observability = {
      enable = lib.mkForce true;
      grafana.enable = lib.mkForce true;
      ntfy.enable = lib.mkForce true;
    };
    ai = {
      enable = lib.mkForce true;
      modelDownloader.enable = lib.mkForce false;
    };
    syncthing.enable = lib.mkForce true;
    vaultwarden.enable = lib.mkForce true;
    power.ups.enable = lib.mkForce false;
  };

  environment.systemPackages = [ guestTest secretAdversarialTest encryptedGuestTest reconfigureTest pkgs.parted pkgs.e2fsprogs ];

  systemd.services.nas-vm-test-repository = {
    description = "Materialize the NAS source tree for in-VM validation";
    wantedBy = [ "multi-user.target" ];
    before = [ "nas-protected-services.target" ];
    serviceConfig.Type = "oneshot";
    script = ''
      set -euo pipefail
      if [[ ! -d /var/lib/nas-test/repo/.git ]]; then
        rm -rf /var/lib/nas-test/repo
        install -d -m 0755 /var/lib/nas-test/repo
        cp -R ${sourceTree}/. /var/lib/nas-test/repo/
        chmod -R u+w /var/lib/nas-test/repo
        cd /var/lib/nas-test/repo
        ${pkgs.git}/bin/git init -q
        ${pkgs.git}/bin/git config user.name "NixOS NAS VM"
        ${pkgs.git}/bin/git config user.email "vm-test@nas.local"
        ${pkgs.git}/bin/git add -A
        ${pkgs.git}/bin/git commit -q -m "VM test source"
      fi
    '';
  };
}
