{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cockpitPort
    cfg
    copypartyDataDir
    copypartyMountRoot
    copypartyUserConfigDir
    nasAuthentikBlueprints
    lanHost
    llamaCppPackage
    nasAlert
    nasCockpitApi
    nasDoctor
    nasIdentitySync
    nasPythonApplication
    nasPreflight
    nasSecrets
    nasSetup
    nasState
    nasUpdate
    nasUpsInitPassword
    nasZfsCreateEncryptedDataset
    nasZfsExportRecoveryKey
    nasZfsLock
    nasZfsMountCheck
    nasZfsUnlock
  ;
  copypartyUserSeed = pkgs.writeText "00-local-overrides.conf" ''
    # Mutable seed; edit through /shares/admin/copyparty-config and reload CopyParty.

    [/shares]
      ${copypartyMountRoot}
      accs:
        r: @application.copyparty.files
        A: @nas_admin

    [/shares/users/''${u%+application.copyparty.files}]
      ${copypartyMountRoot}/users/''${u}
      accs:
        rwmd.: ''${u}
        A: @nas_admin
      flags:
        shr-who: auth

    [/shares/admin/copyparty-config]
      ${copypartyUserConfigDir}
      accs:
      A: @nas_admin
      flags:
        noidx: .*
        nohtml

    ${lib.optionalString cfg.tftp.enable ''
    [/tftp]
      ${copypartyMountRoot}/tftp
      accs:
        # CopyParty evaluates TFTP as anonymous `*`.
        ${if cfg.tftp.writable then "rw" else "r"}: *
      flags:
        noidx: .*
        nohtml
        no-readme
        no-logues
        chmod_f: 660
        chmod_d: 770
    ''}

  '';

in
{
  config = {
    systemd.sockets.cockpit = {
      wantedBy = lib.mkOverride 90 [ "multi-user.target" ];
      partOf = lib.mkOverride 90 [ ];
      listenStreams = lib.mkOverride 90 (
        # The leading "" resets the packaged unit's ListenStream=9090 (same
        # trick the nixpkgs cockpit module uses); without it systemd binds both
        # 9090 and the loopback streams. Cockpit is reachable only through the
        # Caddy reverse proxy; it never binds a network-facing listener. Caddy
        # proxies /console to loopback.
        [ "" "127.0.0.1:${toString cockpitPort}" "[::1]:${toString cockpitPort}" ]
      );
      socketConfig.BindIPv6Only = "ipv6-only";
      unitConfig = {
        ConditionPathExists = lib.mkOverride 90 [ ];
        DefaultDependencies = false;
      };
      conflicts = [ "shutdown.target" ];
      before = [ "shutdown.target" ];
      requires = [ "sysinit.target" ];
      after = [ "sysinit.target" "basic.target" ];
    };

    services.journald.extraConfig = ''
      Storage=persistent
      SystemMaxUse=2G
      MaxRetentionSec=30day
      Compress=yes
    '';
    networking.nftables.enable = lib.mkIf cfg.networking.firewall.enable true;

    # Seed mutable upstream configuration only when absent.
    # Per-type ZFS app data (copyparty) lives under cfg.zfsRoot; main partition
    # retains only Caddy, PAM/Cockpit, and ZFS unencrypt.
    systemd.tmpfiles.rules = [
      "d ${copypartyDataDir}/root 0750 copyparty copyparty -"
      # Keep the bind target empty until the ZFS mount guard succeeds.
      "d ${copypartyMountRoot} 2770 copyparty copyparty -"
      "d ${copypartyUserConfigDir} 0770 copyparty copyparty -"
      "C ${copypartyUserConfigDir}/00-local-overrides.conf 0660 copyparty copyparty - ${copypartyUserSeed}"
      "d /var/lib/nas-identity-sync 0700 root root -"
      "d /var/lib/nas-setup 0770 root wheel -"
      "d ${cfg.zfsRoot}/nas-control 0750 root nas-operations -"
      "L+ /var/lib/nas-control - - - - ${cfg.zfsRoot}/nas-control"
      "d /run/nas-operations 2770 root nas-operations -"
      "d /run/nas-state 0700 root root -"
      "d /var/log/journal 2755 root systemd-journal -"
      "f /run/lock/nas-update.lock 0660 root wheel -"
      "f /run/lock/nas-secrets.lock 0660 root wheel -"
      "f /run/lock/nas-identity-sync.lock 0660 root wheel -"
    ];

    environment.systemPackages = with pkgs; [
      copyparty
      (lib.lowPrio nasPythonApplication)
      keepassxc
      nasSecrets
      nasSetup
      nasState
      nasDoctor
      nasIdentitySync
      nasCockpitApi
      nasPreflight
      nasUpdate
      nasZfsMountCheck
      nasZfsUnlock
      nasZfsLock
      nasZfsCreateEncryptedDataset
      nasZfsExportRecoveryKey
      nasUpsInitPassword
      zfs
      sanoid
      smartmontools
      pciutils
      git
      vim
      curl
      jq
      skopeo
    ]
    ++ lib.optional cfg.hardware.llamaCpp.enable llamaCppPackage
    ++ lib.optional cfg.alerting.enable nasAlert
    ++ lib.optional cfg.backup.enable restic;

    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "no";
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = false;
        X11Forwarding = false;
        AllowGroups = [ "nas-administrators" ];
      };
    };

    security.sudo.wheelNeedsPassword = true;
    boot.kernel.sysctl = {
      "kernel.yama.ptrace_scope" = 2;
      "kernel.kptr_restrict" = 2;
      "kernel.dmesg_restrict" = 1;
      "fs.protected_fifos" = 2;
      "fs.protected_regular" = 2;
    };

    nix.package = lib.mkDefault pkgs.nix;
    nix.settings = {
      experimental-features = [ "nix-command" "flakes" ];
      auto-optimise-store = true;
    };
    nix.gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 30d";
    };
  };
}
