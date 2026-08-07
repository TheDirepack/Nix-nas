{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    adminAccount
    adminGroups
    adminKeys
    bootLoaderConfigured
    cfg
    gpuVendors
    rootFilesystemConfigured
    hasAmdGpu
    hasNvidiaGpu
    hostSystem
    isX86_64
    llamaBackend
    loopbackServicePorts
    observabilityGidCollisions
    observabilityUidCollisions
    supportedHostSystems
    vmStoragePath
  ;
in
{
  config = {
    assertions = [
      {
        assertion = lib.hasPrefix "/" cfg.zfsRoot && cfg.zfsRoot != "/";
        message = "nas.zfsRoot must be an absolute non-root path.";
      }
      {
        assertion = lib.hasPrefix "/" cfg.configurationDir;
        message = "nas.configurationDir must be an absolute path.";
      }
      {
        assertion = lib.hasPrefix "/" cfg.firstStart.configFile;
        message = "nas.firstStart.configFile must be an absolute path.";
      }
      {
        assertion = cfg.trustedInterfaces == lib.unique cfg.trustedInterfaces;
        message = "nas.trustedInterfaces must not contain duplicate interface names.";
      }
      {
        assertion = !lib.elem "lo" cfg.trustedInterfaces && lib.all (interface: interface != "") cfg.trustedInterfaces;
        message = "nas.trustedInterfaces must contain real non-loopback interface names.";
      }
      {
        assertion = !cfg.tftp.enable || cfg.tftp.internalPort >= 1024;
        message = "nas.tftp.internalPort must be unprivileged because CopyParty does not run as root.";
      }
      {
        assertion = !cfg.tftp.enable || !(lib.elem cfg.tftp.internalPort ([ 443 5353 ] ++ lib.optionals cfg.syncthing.enable [ 21027 22000 ]));
        message = "nas.tftp.internalPort conflicts with HTTPS/HTTP3, mDNS, or an enabled Syncthing UDP port.";
      }
      {
        assertion = !cfg.tftp.enable || cfg.tftp.responsePortStart <= cfg.tftp.responsePortEnd;
        message = "nas.tftp.responsePortStart must not exceed responsePortEnd.";
      }
      {
        assertion = !cfg.tftp.enable || !(cfg.tftp.internalPort >= cfg.tftp.responsePortStart && cfg.tftp.internalPort <= cfg.tftp.responsePortEnd);
        message = "nas.tftp.internalPort must not fall inside the TFTP response-port range.";
      }
      {
        assertion = cfg.zfsPool != "" && lib.hasPrefix "${cfg.zfsPool}/" cfg.zfsDataset;
        message = "nas.zfsDataset must be a child dataset of nas.zfsPool, such as tank/nas.";
      }
      {
        assertion = !cfg.virtualization.enable || lib.hasPrefix "${cfg.zfsRoot}/" vmStoragePath;
        message = "The virtual-machine storage path must be a child of nas.zfsRoot so the ZFS mount guard and encryption lifecycle remain authoritative.";
      }
      {
        assertion = !cfg.power.ups.enable || lib.hasPrefix "/" cfg.power.ups.passwordFile;
        message = "nas.power.ups.passwordFile must be an absolute boot-available path.";
      }
      {
        assertion = !cfg.power.ups.enable || cfg.power.ups.mode != "netclient" || cfg.power.ups.monitorSystem != "";
        message = "NUT netclient mode requires nas.power.ups.monitorSystem.";
      }
      {
        assertion = !cfg.power.ups.enable || cfg.power.ups.mode == "netclient" || cfg.power.ups.driver != "";
        message = "Local NUT modes require a non-empty UPS driver.";
      }
      {
        assertion = !cfg.power.ups.enable || cfg.power.ups.mode != "netserver" || cfg.power.ups.serverListenAddresses != [ ];
        message = "NUT netserver mode requires at least one upsd listen address.";
      }
      {
        assertion = !cfg.power.ups.enable || !cfg.power.ups.web.enable || cfg.power.ups.web.upsdAddress != "";
        message = "NUT Web GUI requires a non-empty upsd address.";
      }
      {
        assertion = !cfg.networking.firewall.enable || cfg.networking.enable;
        message = "nas.networking.firewall.enable requires nas.networking.enable.";
      }
      {
        assertion = !cfg.observability.enable || cfg.observability.serviceUid >= 100 && cfg.observability.serviceUid < 1000;
        message = "nas.observability.serviceUid must be a system UID between 100 and 999.";
      }
      {
        assertion = !cfg.observability.enable || observabilityUidCollisions == [ ];
        message = "nas.observability.serviceUid collides with another declared account: ${lib.concatStringsSep ", " observabilityUidCollisions}.";
      }
      {
        assertion = !cfg.observability.enable || cfg.observability.serviceGid >= 100 && cfg.observability.serviceGid < 1000;
        message = "nas.observability.serviceGid must be a system GID between 100 and 999.";
      }
      {
        assertion = !cfg.observability.enable || observabilityGidCollisions == [ ];
        message = "nas.observability.serviceGid collides with another declared group: ${lib.concatStringsSep ", " observabilityGidCollisions}.";
      }
      {
        assertion = loopbackServicePorts == lib.unique loopbackServicePorts;
        message = "NAS loopback listeners must use unique ports across Cockpit, identity, observability, UPS, Syncthing, Vaultwarden, and AI services.";
      }
      {
        assertion = cfg.observability.thresholds.filesystemCriticalPercent < cfg.observability.thresholds.filesystemWarningPercent;
        message = "The critical filesystem threshold must be lower than the warning threshold.";
      }
      {
        assertion = cfg.scheduler.backend != "cockpit-scheduler" || cfg.scheduler.package != null;
        message = "nas.scheduler.backend = cockpit-scheduler requires a reproducibly packaged plugin in nas.scheduler.package.";
      }
      {
        assertion = cfg.adminUser == "admin";
        message = "nas.adminUser is the immutable runtime identity anchor and must remain admin.";
      }
      {
        assertion = adminAccount != null;
        message = "users.users.${cfg.adminUser} must be declared.";
      }
      {
        assertion = adminAccount == null || (adminAccount.isNormalUser or false);
        message = "nas.adminUser must be a normal Linux user.";
      }
      {
        assertion = adminAccount == null || lib.elem "wheel" adminGroups;
        message = "nas.adminUser must belong to the wheel group.";
      }
      {
        assertion = lib.elem hostSystem supportedHostSystems;
        message = "This appliance release supports x86_64-linux only; got ${hostSystem}.";
      }
      {
        assertion = cfg.hardware.gpuVendors == lib.unique cfg.hardware.gpuVendors;
        message = "nas.hardware.gpuVendors must not contain duplicate vendors.";
      }
      {
        assertion = !hasNvidiaGpu || isX86_64;
        message = "The standard NVIDIA driver integration in this profile is supported only on x86_64. Use CPU/Vulkan with a supported ARM graphics stack or add board-specific NVIDIA modules.";
      }
      {
        assertion = llamaBackend != "cuda" || (isX86_64 && hasNvidiaGpu);
        message = "nas.hardware.llamaCpp.backend = cuda requires x86_64 and nvidia in nas.hardware.gpuVendors.";
      }
      {
        assertion = llamaBackend != "rocm" || (isX86_64 && hasAmdGpu);
        message = "nas.hardware.llamaCpp.backend = rocm requires x86_64 and amd in nas.hardware.gpuVendors.";
      }
      {
        assertion = llamaBackend != "vulkan" || gpuVendors != [ ];
        message = "nas.hardware.llamaCpp.backend = vulkan requires at least one declared GPU vendor.";
      }
      {
        assertion = lib.versionAtLeast pkgs.caddy.version "2.11.3";
        message = "Caddy must be version 2.11.3 or newer.";
      }
      {
        assertion = lib.versionAtLeast pkgs.authentik.version "2025.12.4";
        message = "Authentik 2025.12.4 or newer is required for the patched Caddy forward-auth implementation.";
      }
      {
        assertion =
          !cfg.vaultwarden.enable
          || lib.versionAtLeast config.services.vaultwarden.package.version "1.36.0";
        message = "Vaultwarden 1.36.0 or newer is required for native OpenID Connect SSO.";
      }
      {
        assertion = !cfg.alerting.enable || (cfg.observability.enable && cfg.observability.ntfy.enable);
        message = "nas.alerting.enable requires both nas.observability.enable and nas.observability.ntfy.enable.";
      }
      {
        assertion = lib.hasPrefix "/" cfg.secrets.keepassDatabase;
        message = "nas.secrets.keepassDatabase must be an absolute path.";
      }
      {
        assertion = cfg.secrets.keepassKeyFile == null || lib.hasPrefix "/" cfg.secrets.keepassKeyFile;
        message = "nas.secrets.keepassKeyFile must be null or an absolute path.";
      }
      {
        assertion = !cfg.backup.enable || cfg.backup.passwordFile != "";
        message = "Restic boot/system recovery backups require nas.backup.passwordFile.";
      }
      {
        assertion = !cfg.backup.enable || cfg.backup.repositoryFile != "" || cfg.backup.allowSamePoolRepository;
        message = "A same-pool Restic repository requires nas.backup.allowSamePoolRepository = true and is local rollback only.";
      }
      {
        assertion = !cfg.backup.enable || (lib.hasPrefix "/" cfg.backup.stagingPath && !lib.hasPrefix "/run/" cfg.backup.stagingPath);
        message = "nas.backup.stagingPath must be an absolute disk-backed path outside /run.";
      }
      {
        assertion = !cfg.backup.enable || !cfg.backup.restoreVerification.enable
          || (lib.hasPrefix "/" cfg.backup.restoreVerification.targetPath
            && !lib.hasPrefix "/run/" cfg.backup.restoreVerification.targetPath
            && cfg.backup.restoreVerification.targetPath != cfg.backup.stagingPath);
        message = "Backup restore verification requires a distinct absolute disk-backed target outside /run.";
      }
      {
        assertion = !cfg.installationReady || cfg.testing.installationReadyFixture || cfg.zfsReplication.enable || (cfg.backup.enable && cfg.backup.repositoryFile != "");
        message = "installationReady requires an off-pool Restic repository or enabled ZFS replication.";
      }
      {
        assertion =
          !cfg.backup.enable
          || (lib.hasPrefix "/" cfg.backup.passwordFile
            && lib.hasPrefix "/" cfg.secrets.keepassDatabase
            && (cfg.backup.repositoryFile == "" || lib.hasPrefix "/" cfg.backup.repositoryFile)
            && (cfg.backup.localRepository == "" || lib.hasPrefix "/" cfg.backup.localRepository));
        message = "Restic passwordFile, KDBX path, repositoryFile, and localRepository must be absolute paths when set.";
      }
      {
        assertion =
          !cfg.zfsReplication.enable
          || (cfg.zfsReplication.target != ""
            && cfg.zfsReplication.target != cfg.zfsDataset
            && !(lib.hasPrefix "-" cfg.zfsReplication.target)
            && builtins.match "^[^[:space:]]+$" cfg.zfsReplication.target != null);
        message = "nas.zfsReplication.enable requires a non-empty destination distinct from nas.zfsDataset, without whitespace or a leading dash.";
      }
      {
        assertion = lib.all (argument: argument != "" && !(lib.hasInfix "\n" argument)) cfg.zfsReplication.extraArgs;
        message = "nas.zfsReplication.extraArgs may not contain empty strings or newlines.";
      }
      {
        assertion = !cfg.installationReady || cfg.trustedInterfaces != [ ];
        message = "Set nas.trustedInterfaces to the actual LAN interface before installation.";
      }
      {
        assertion = !cfg.installationReady || !cfg.networking.firewall.enable || cfg.networking.firewall.seedDefaults;
        message = "installationReady requires the mandatory firewalld baseline when the managed firewall is enabled.";
      }
      {
        assertion = !cfg.installationReady || adminKeys != [ ];
        message = "Add at least one SSH public key for the administrator before installation.";
      }
      {
        assertion = !cfg.installationReady || (cfg.adminPasswordHashFile != null && lib.hasPrefix "/" cfg.adminPasswordHashFile);
        message = "Set nas.adminPasswordHashFile to an absolute root-only password-hash file before installation.";
      }
      {
        assertion =
          !cfg.installationReady
          || (builtins.match "^[0-9a-fA-F]{8}$" config.networking.hostId != null
            && config.networking.hostId != "00000000"
            && config.networking.hostId != "8425e349"
            && config.networking.hostId != "4b327644");
        message = "networking.hostId must be a unique stable eight-hex-digit value.";
      }
      {
        assertion = !cfg.installationReady || cfg.testing.installationReadyFixture || rootFilesystemConfigured;
        message = "Declare the actual root filesystem before installation; the evaluated configuration has no root filesystem entry.";
      }
      {
        assertion = !cfg.installationReady || bootLoaderConfigured;
        message = "Configure and verify a boot loader in local.nix before installation (systemd-boot for UEFI or GRUB where appropriate).";
      }
      {
        assertion = !cfg.installationReady || cfg.testing.installationReadyFixture || cfg.zfsImportAtBoot;
        message = "Enable nas.zfsImportAtBoot only after the pool and child dataset have been created and verified.";
      }
    ];
    warnings =
      lib.optional (cfg.installationReady && !cfg.observability.enable && !cfg.alerting.enable)
        "NAS alerting is disabled; disk, pool, snapshot, update, and service failures will only appear in Cockpit/journald."
      ++ lib.optional (cfg.installationReady && !cfg.backup.enable)
        "Boot/system recovery backup is disabled. ZFS snapshots do not protect the boot device or appliance configuration."
      ++ lib.optional (cfg.backup.enable && cfg.backup.repositoryFile == "")
        "The explicitly permitted same-pool Restic repository is local rollback only and does not protect against pool loss."
      ++ lib.optional cfg.tftp.writable
        "Writable CopyParty TFTP is unauthenticated. Enable it only temporarily on a tightly trusted provisioning interface."
      ++ lib.optional cfg.zfsEncryption.enable
        "The ZFS encryption key is unlocked interactively from KeePassXC after boot. Keep an off-host KDBX backup and a separately tested recovery copy."
      ++ lib.optional (cfg.power.ups.enable && cfg.power.ups.web.allowControl)
        "NUT Web GUI control actions are enabled. Treat SET, instant commands, and forced shutdown as privileged destructive operations."
      ++ lib.optional (cfg.power.ups.enable && cfg.power.ups.mode == "netserver" && lib.all (address: lib.elem address [ "127.0.0.1" "::1" ]) cfg.power.ups.serverListenAddresses)
        "NUT netserver mode currently listens only on loopback; add the NAS LAN address before expecting remote NUT clients to connect."
      ++ lib.optional cfg.virtualization.enable
        "Virtual machines share CPU, memory, storage, and shutdown time with the NAS. Reserve resources and test UPS-driven guest shutdown before production use."
      ++ lib.optional cfg.webdav.adminEnable
        "The CopyParty admin credential is enabled for direct WebDAV and bypasses browser MFA; use it only when strictly necessary."
      ++ lib.optional (cfg.syncthing.enable && cfg.syncthing.internetDiscovery)
        "Syncthing global discovery, relays, and NAT traversal are enabled. Device authentication still applies, but connections are no longer LAN-only."
      ++ lib.optional (cfg.autoUpdate.enable && cfg.autoUpdate.apply)
        "Unattended updates are configured to activate immediately; test manual update and rollback workflows first, and remember that a running-system test cannot validate a newly selected kernel before reboot.";
  };
}
