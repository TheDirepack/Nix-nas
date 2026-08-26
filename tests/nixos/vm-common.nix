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
  authentikProxy = pkgs.authentik-outposts.proxy;

  # The full-stack source harness still contains the final V1-era fixture
  # vocabulary. Render its VM executable against the current V2 contracts:
  # schema-v2 setup, base identity roles, canonical application capabilities,
  # and no retired request-time gate. The browser/Caddy assertions below remain
  # the request-time authorization coverage for those capabilities.
  guestTestRaw = builtins.readFile ../vm/guest-test.sh;
  guestTestSchemaV2 = builtins.replaceStrings
    [
      "\"schemaVersion\": 1"
      "  \"features\": {},\n"
      "\"groups\": [\"nas_admin\", \"nas_allow_files\", \"nas_allow_ai\", \"nas_allow_vault\", \"nas_allow_syncthing\"]"
      "\"groups\": [\"nas_users\", \"nas_allow_files\", \"nas_allow_vault\", \"nas_allow_syncthing\"]"
      "--group nas_allow_files"
    ]
    [
      "\"schemaVersion\": 2"
      ""
      "\"groups\": [\"nas_admin\"]"
      "\"groups\": [\"nas_users\"]"
      "--group nas_users"
    ]
    guestTestRaw;
  guestTestCanonicalGroups = builtins.replaceStrings
    [ "nas_allow_files" "nas_allow_ai" "nas_allow_vault" "nas_allow_syncthing" ]
    [
      "application.copyparty.files"
      "application.ai-workspace.access"
      "application.vaultwarden.access"
      "application.syncthing.access"
    ]
    guestTestSchemaV2;
  guestTestWithoutGateUnit = builtins.replaceStrings
    [ "  nas-on-demand-gate.service caddy.service; do" ]
    [ "  caddy.service; do" ]
    guestTestCanonicalGroups;
  retiredGateStart = "gate_deny=\"$(http_code --unix-socket /run/nas-on-demand/gate.sock";
  retiredGateEnd = "pass \"malformed trusted identity headers remain fail-closed inside the installed gate\"\n";
  retiredGateStartParts = lib.splitString retiredGateStart guestTestWithoutGateUnit;
  retiredGateTail =
    if builtins.length retiredGateStartParts == 2
    then builtins.elemAt retiredGateStartParts 1
    else throw "ordinary VM fixture no longer contains the expected retired gate block start";
  retiredGateEndParts = lib.splitString retiredGateEnd retiredGateTail;
  guestTestWithoutRetiredGate =
    if builtins.length retiredGateEndParts == 2
    then (builtins.elemAt retiredGateStartParts 0) + (builtins.elemAt retiredGateEndParts 1)
    else throw "ordinary VM fixture no longer contains the expected retired gate block end";
  capabilityGrantMarker =
    "  --unix-socket /run/copyparty/http.sock http://localhost/ >/dev/null\nnas-identity-sync status | jq -e '";
  capabilityGrantBlock = builtins.concatStringsSep "\n" [
    "  --unix-socket /run/copyparty/http.sock http://localhost/ >/dev/null"
    "AUTHENTIK_BOOTSTRAP_TOKEN=\"$(< /run/nas-secrets/authentik/api-token)\""
    "alice_pk=\"$(authentik_api GET 'core/users/?include_groups=true&page_size=100' | jq -er '.results[] | select(.username == \"alice\") | (.num_pk // .pk)')\""
    "for capability_group in application.copyparty.files application.syncthing.access application.vaultwarden.access; do"
    "  group_pk=\"$(authentik_api GET 'core/groups/?page_size=100' | jq -er --arg group \"$capability_group\" '.results[] | select(.name == $group) | .pk')\""
    "  authentik_api POST \"core/groups/$group_pk/add_user/\" \"$(jq -cn --argjson pk \"$alice_pk\" '{pk: $pk}')\" >/dev/null"
    "done"
    "pass \"Alice application capabilities are assigned through canonical Authentik groups\""
    "nas-identity-sync status | jq -e '"
  ];
  guestTestSource = builtins.replaceStrings
    [ capabilityGrantMarker ]
    [ capabilityGrantBlock ]
    guestTestWithoutRetiredGate;

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
      (python3.withPackages (pythonPackages: [ pythonPackages.hypothesis pythonPackages.selenium ]))
      procps
      systemd
      util-linux
      zfs
      authentikProxy
    ];
    text = ''
      ${builtins.readFile ../../scripts/lib/nas-vm-cleanup.sh}
      ${builtins.readFile ../../scripts/lib/nas-vm-process-cleanup.sh}
      ${builtins.readFile ../vm/timeout-budget.sh}
      ${builtins.readFile ../../scripts/lib/nas-vm-secret-input.sh}
      # Dedicated CI jobs have already qualified source tests, tooling, the
      # Cockpit production bundle, and Nix reference configurations before QEMU.
      # Keep nas-preflight exercised in the installed VM without recursively
      # rerunning those expensive owners during first-run and command smoke.
      export NAS_PREFLIGHT_SKIP_TESTS=1
      export NAS_PREFLIGHT_SKIP_TOOLING=1
      export NAS_PREFLIGHT_SKIP_NIX=1
      export NAS_PREFLIGHT_SKIP_COCKPIT_BUNDLE=1

      ${builtins.readFile ../../scripts/lib/nas-vm-profile.sh}
      nas_vm_profile_install

      ${guestTestSource}
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
    text = ''
      ${builtins.readFile ../vm/timeout-budget.sh}
      ${builtins.readFile ../vm/reconfigure-system.sh}
    '';
  };
  encryptedGuestTest = pkgs.writeShellApplication {
    name = "nas-vm-encrypted-guest-test";
    runtimeInputs = with pkgs; [
      bash
      coreutils
      gnugrep
      jq
      keepassxc
      procps
      systemd
      util-linux
      zfs
    ];
    text = ''
      ${builtins.readFile ../../scripts/lib/nas-vm-cleanup.sh}
      ${builtins.readFile ../../scripts/lib/nas-vm-process-cleanup.sh}
      ${builtins.readFile ../vm/timeout-budget.sh}
      ${builtins.readFile ../../scripts/lib/nas-vm-secret-input.sh}
      ${builtins.readFile ../../scripts/lib/nas-vm-profile.sh}
      nas_vm_profile_install
      ${builtins.readFile ../vm/encrypted-guest-test.sh}
    '';
  };
in
{
  networking.hostName = lib.mkForce "nas-test";
  networking.hostId = lib.mkForce "c1a05eed";
  networking.useDHCP = lib.mkDefault true;
  # Browser checks use the same public hostname as the Authentik provider. Keep
  # that name resolvable inside the isolated guest without depending on a host
  # DNS service or a physical NIC.
  networking.extraHosts = "127.0.0.1 nas-test.local";
  boot.supportedFilesystems = [ "zfs" ];

  # The NixOS test kernel does not expose the per-service cgroup pressure file
  # that systemd 260 otherwise tries to bind into copyparty's private mount
  # namespace. The production service keeps its normal host accounting policy.
  systemd.services.copyparty.serviceConfig.MemoryPressureWatch = lib.mkForce "off";

  users.users.admin = {
    isNormalUser = true;
    linger = true;
    autoSubUidGidRange = true;
    extraGroups = [ "wheel" "nas-administrators" "nas-operations" ];
    hashedPasswordFile = lib.mkForce (toString (pkgs.writeText "vm-admin-password-hash" "$6$nixosnas$Hsg1F2Cw2J25Jj9ZMzgEC8uiPgOS.DP/A8Pi28n.oXWw.CuB529luz/tBoCaxVXkuP6NqDmqUUUf5scB1/7jU1"));
    openssh.authorizedKeys.keys = lib.mkAfter [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICITestFixtureOnlyKeyMaterial000000000000000 nas-ci" ];
  };
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
    # The guest fixture and the identity bootstrap must agree on the
    # browser-facing public host, including the HTTPS port, or the bootstrap
    # portal provider ends up with an external host the fixtures reject.
    identity.publicHost = lib.mkForce "nas-test.local:8443";
    # The guest suite creates its first-run plan here; keep the installed
    # Cockpit status source aligned with the plan used by the test.
    firstStart.configFile = "/var/lib/nas-test/setup/first-run.json";
    # The browser qualification logs into Cockpit through its direct PAM
    # recovery listener. Keep this credential scoped to the disposable VM
    # fixture; production configurations must provide their own root-only hash.
    adminPasswordHashFile = lib.mkForce (toString (pkgs.writeText "vm-admin-password-hash" "$6$nixosnas$Hsg1F2Cw2J25Jj9ZMzgEC8uiPgOS.DP/A8Pi28n.oXWw.CuB529luz/tBoCaxVXkuP6NqDmqUUUf5scB1/7jU1"));
    zfsImportAtBoot = lib.mkForce false;
    zfsEncryption.enable = lib.mkDefault false;
    zfsEncryption.acknowledgeUnencrypted = lib.mkForce true;
    autoUpdate.enable = lib.mkForce false;
    backup.enable = lib.mkForce false;
    virtualization.enable = lib.mkForce false;
    # Non-core features are stripped from the appliance build for now
    # (single revertible commit); flip these back to re-enable.
    tftp.enable = lib.mkForce false;
    alerting.enable = lib.mkForce true;
    observability = {
      enable = lib.mkForce true;
      grafana.enable = lib.mkForce true;
      ntfy.enable = lib.mkForce true;
    };
    ai = {
      enable = lib.mkForce false;
      modelDownloader.enable = lib.mkForce false;
    };
    syncthing.enable = lib.mkForce false;
    vaultwarden.enable = lib.mkForce false;
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
