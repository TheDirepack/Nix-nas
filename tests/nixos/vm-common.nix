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
      # Dedicated CI jobs have already qualified source tests, tooling, the
      # Cockpit production bundle, and Nix reference configurations before QEMU.
      # Keep nas-preflight exercised in the installed VM without recursively
      # rerunning those expensive owners during first-run and command smoke.
      export NAS_PREFLIGHT_SKIP_TESTS=1
      export NAS_PREFLIGHT_SKIP_TOOLING=1
      export NAS_PREFLIGHT_SKIP_NIX=1
      export NAS_PREFLIGHT_SKIP_COCKPIT_BUNDLE=1

      # guest-test.sh has stable top-level log() boundaries. Emit a phase start
      # immediately, then report the previous phase when the next boundary is
      # reached. For the known long first-run command, emit a heartbeat every
      # minute so a timeout still leaves useful elapsed-time evidence instead of
      # losing the active phase's duration entirely.
      NAS_VM_PHASE_STARTED=$SECONDS
      NAS_VM_PHASE_NAME=""
      NAS_VM_FIRST_RUN_TIMER_PID=""

      nas_vm_stop_first_run_timer() {
        if [[ -n "$NAS_VM_FIRST_RUN_TIMER_PID" ]]; then
          kill "$NAS_VM_FIRST_RUN_TIMER_PID" >/dev/null 2>&1 || true
          wait "$NAS_VM_FIRST_RUN_TIMER_PID" 2>/dev/null || true
          NAS_VM_FIRST_RUN_TIMER_PID=""
        fi
      }

      nas_vm_start_first_run_timer() {
        nas_vm_stop_first_run_timer
        (
          started=$SECONDS
          while sleep 60; do
            printf 'VM-FIRST-RUN-TIMING: %ss elapsed\n' "$((SECONDS - started))"
          done
        ) &
        NAS_VM_FIRST_RUN_TIMER_PID=$!
      }

      nas_vm_profile_command() {
        local command=$1 now phase_name
        case "$command" in
          log\ *)
            # guest-test.sh temporarily owns EXIT while browser credentials
            # exist. Re-arm profiling at every stable phase boundary after that
            # temporary trap has been cleared.
            trap nas_vm_profile_cleanup EXIT
            nas_vm_stop_first_run_timer
            now=$SECONDS
            if [[ -n "$NAS_VM_PHASE_NAME" ]]; then
              printf 'VM-PHASE-TIMING: %s: %ss (complete)\n' "$NAS_VM_PHASE_NAME" "$((now - NAS_VM_PHASE_STARTED))"
            fi
            phase_name="''${command#log }"
            phase_name="''${phase_name#\"}"
            phase_name="''${phase_name%\"}"
            NAS_VM_PHASE_NAME=$phase_name
            NAS_VM_PHASE_STARTED=$now
            printf 'VM-PHASE-START: %s\n' "$NAS_VM_PHASE_NAME"
            ;;
          run_as_admin*"timeout 1200 nas-setup first-run"*)
            printf 'VM-FIRST-RUN-START: %s\n' "$NAS_VM_PHASE_NAME"
            nas_vm_start_first_run_timer
            ;;
          jq\ -e*)
            # The first jq assertion immediately following first-run marks the
            # end of that long command. Other jq calls harmlessly see no timer.
            nas_vm_stop_first_run_timer
            ;;
        esac
      }

      nas_vm_profile_cleanup() {
        local rc=$? now=$SECONDS
        nas_vm_stop_first_run_timer
        if [[ -n "$NAS_VM_PHASE_NAME" ]]; then
          if [[ $rc -eq 0 ]]; then
            printf 'VM-PHASE-TIMING: %s: %ss (complete)\n' "$NAS_VM_PHASE_NAME" "$((now - NAS_VM_PHASE_STARTED))"
          else
            printf 'VM-PHASE-TIMING: %s: %ss (failed)\n' "$NAS_VM_PHASE_NAME" "$((now - NAS_VM_PHASE_STARTED))" >&2
          fi
        fi
        return "$rc"
      }

      trap 'nas_vm_profile_command "$BASH_COMMAND"' DEBUG
      trap nas_vm_profile_cleanup EXIT

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

  # The NixOS test kernel does not expose the per-service cgroup pressure file
  # that systemd 260 otherwise tries to bind into copyparty's private mount
  # namespace. The production service keeps its normal host accounting policy.
  systemd.services.copyparty.serviceConfig.MemoryPressureWatch = lib.mkForce "off";

  users.users.admin.extraGroups = lib.mkAfter [ "wheel" ];
  security.sudo.wheelNeedsPassword = lib.mkForce false;

  services.openssh.settings = {
    PasswordAuthentication = lib.mkForce false;
    KbdInteractiveAuthentication = lib.mkForce false;
    PermitRootLogin = lib.mkForce "no";
  };

  nas = {
    installationReady = lib.mkForce true;
    identity.authentikOutpostPort = lib.mkForce 9010;
    testing.installationReadyFixture = true;
    configurationDir = lib.mkForce "/var/lib/nas-test/repo";
    # The guest suite creates its first-run plan here; keep the installed
    # Cockpit status source aligned with the plan used by the test.
    firstStart.configFile = "/var/lib/nas-test/setup/first-run.json";
    # The browser qualification logs into Cockpit through its direct PAM
    # recovery listener. Keep this credential scoped to the disposable VM
    # fixture; production configurations must provide their own root-only hash.
    adminPasswordHashFile = lib.mkForce (toString (pkgs.writeText "vm-admin-password-hash" "$6$nixosnas$Hsg1F2Cw2J25Jj9ZMzgEC8uiPgOS.DP/A8Pi28n.oXWw.CuB529luz/tBoCaxVXkuP6NqDmqUUUf5scB1/7jU1"));
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
