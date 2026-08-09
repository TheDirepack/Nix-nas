{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cockpitPort
    capabilityRegistryDocument
    cfg
    copypartyMountRoot
    copypartyUserConfigDir
    nasAuthentikBlueprints
    featureCatalog
    lanHost
    llamaCppPackage
    nasAlert
    nasCockpitApi
    nasDoctor
    nasFeatureControl
    nasIdentitySync
    nasMigrateState
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
    secretRoot
    serviceRegistry
  ;
  copypartyUserSeed = pkgs.writeText "00-local-overrides.conf" ''
    # Mutable seed; edit through /shares/admin/copyparty-config and reload CopyParty.

    [/shares]
      ${copypartyMountRoot}
      accs:
        A: @nas_admin

    [/shares/users/''${u%+nas_allow_files}]
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
        noidx
        nohtml

    ${lib.optionalString cfg.tftp.enable ''
    [/tftp]
      ${copypartyMountRoot}/tftp
      accs:
        # CopyParty evaluates TFTP as anonymous `*`.
        ${if cfg.tftp.writable then "rw" else "r"}: *
      flags:
        noidx
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
      wantedBy = lib.mkOverride 90 [ "sockets.target" ];
      partOf = lib.mkOverride 90 [ ];
      listenStreams = lib.mkOverride 90 (
        if cfg.hostPolicy.directCockpitRecovery
        then [ "0.0.0.0:${toString cockpitPort}" "[::]:${toString cockpitPort}" ]
        else [ "127.0.0.1:${toString cockpitPort}" "[::1]:${toString cockpitPort}" ]
      );
      socketConfig.BindIPv6Only = "ipv6-only";
      unitConfig.ConditionPathExists = lib.mkOverride 90 [ ];
      requires = lib.optional (
        cfg.hostPolicy.directCockpitRecovery
        && cfg.networking.enable
        && cfg.networking.firewall.enable
        && cfg.trustedInterfaces != [ ]
        && !cfg.testing.installationReadyFixture
      ) "nas-management-network-guard.service";
      after = lib.optional (
        cfg.hostPolicy.directCockpitRecovery
        && cfg.networking.enable
        && cfg.networking.firewall.enable
        && cfg.trustedInterfaces != [ ]
        && !cfg.testing.installationReadyFixture
      ) "nas-management-network-guard.service";
    };

    services.journald.extraConfig = ''
      Storage=persistent
      SystemMaxUse=2G
      MaxRetentionSec=30day
      Compress=yes
    '';
    networking.nftables.enable = lib.mkIf cfg.networking.firewall.enable true;

    # Seed mutable upstream configuration only when absent.
    systemd.tmpfiles.rules = [
      "d /var/lib/copyparty/root 0750 copyparty copyparty -"
      # Keep the bind target empty until the ZFS mount guard succeeds.
      "d ${copypartyMountRoot} 2770 copyparty copyparty -"
      "d ${copypartyUserConfigDir} 0770 copyparty copyparty -"
      "C ${copypartyUserConfigDir}/00-local-overrides.conf 0660 copyparty copyparty - ${copypartyUserSeed}"
      "d /var/lib/nas-identity-sync 0700 root root -"
      "d /var/lib/nas-setup 0750 root wheel -"
      "d /var/lib/nas-control 0770 nas-feature-gate nas-feature-control -"
      "d /run/nas-operations 2770 root nas-operations -"
      "d /run/nas-state 0700 root root -"
      "f /var/lib/nas-control/feature-control.lock 0660 nas-feature-gate nas-feature-control -"
      "d /var/log/journal 2755 root systemd-journal -"
      "f /run/lock/nas-update.lock 0660 root wheel -"
      "f /run/lock/nas-secrets.lock 0660 root wheel -"
      "f /run/lock/nas-identity-sync.lock 0660 root wheel -"
      "d /blueprints 0755 root root -"
      "L+ /blueprints/nas-user-settings.yaml - - - - ${nasAuthentikBlueprints}/share/authentik/blueprints/nas-user-settings.yaml"
    ];

    environment.etc."nas-control/capabilities.json".text = builtins.toJSON capabilityRegistryDocument;
    environment.etc."nas-control/capability-registry.schema.json".source = ../../../schemas/capability-registry.schema.json;
    environment.etc."nas-control/features.json".text = builtins.toJSON featureCatalog;
    environment.etc."nas-control/endpoints.json".text = builtins.toJSON nasInternal.serviceRegistryV2;
    environment.etc."nas-control/endpoints-v1.json".text = builtins.toJSON {
      schemaVersion = 1;
      endpoints = serviceRegistry;
    };
    environment.etc."nas-control/feature-catalog.schema.json".source = ../../../schemas/feature-catalog.schema.json;

    environment.systemPackages = with pkgs; [
      copyparty
      nasPythonApplication
      keepassxc
      nasSecrets
      nasSetup
      nasState
      nasDoctor
      nasMigrateState
      nasIdentitySync
      nasFeatureControl
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
        AllowUsers = [ cfg.adminUser ];
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
