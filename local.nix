{ ... }:

# Complete docs/src/admin/configuration.md before enabling installationReady.
{
  imports = [
    ./modules/profiles/core-storage.nix
    ./modules/profiles/identity-sharing.nix
    # Non-core features are stripped from the build for now; re-enable the
    # profiles below when AI and observability ship again.
    # ./modules/profiles/observability.nix
    # ./modules/profiles/local-ai.nix
  ];

  system.stateVersion = "26.05";
  networking.hostId = "00000000";

  users.users.admin = {
    isNormalUser = true;
    description = "NAS Administrator";
    extraGroups = [
      "wheel"
      "video"
      "render"
    ];
    openssh.authorizedKeys.keys = [ ];
  };

  boot.loader.systemd-boot = {
    enable = false;
    configurationLimit = 20;
  };
  boot.loader.efi.canTouchEfiVariables = false;

  nas = {
    adminUser = "admin";
    adminPasswordHashFile = "/etc/nixos/nixos-nas/secrets/admin-password-hash";

    hostPolicy = {
      mutableLocalPasswords = true;
      directCockpitRecovery = false;
    };

    installationReady = false;

    configurationDir = "/etc/nixos/nixos-nas";
    trustedInterfaces = [ ];

    networking.firewall.zone = "nas-lan";

    observability.retentionTime = "30d";

    scheduler.backend = "systemd";

    desktop.enable = false;

    ai = {
      storageRoot = "";

      llamaSwap = {
        port = 9292;
        globalTtl = 600;
      };

      modelDownloader = {
        enable = false;
        port = 9381;
      };

      openWebuiPort = 9380;
    };

    hardware = {
      cpuVendor = "auto";
      gpuVendors = [ ];
      graphicsEnable = true;

      nvidia = {
        openKernelModule = false;
        containerToolkit = false;
      };

      llamaCpp = {
        enable = true;
        backend = "cpu";
      };
    };

    zfsRoot = "/tank";
    zfsPool = "tank";
    zfsDataset = "tank/nas";
    zfsImportAtBoot = false;
    zfsTrimEnable = false;

    zfsEncryption = {
      enable = false;
      algorithm = "aes-256-gcm";
    };

    webdav.adminEnable = false;

    identity = {
      authentikPath = "/identity/";
      bootstrapEmail = "admin@nas.local";
      userGroup = "nas_users";
      guestGroup = "nas_guests";
      disabledGroup = "nas_disabled";
      syncInterval = "5min";
    };

    syncthing.internetDiscovery = false;
    vaultwarden.ssoOnly = true;

    tftp = {
      enable = false;
      writable = false;
      port = 69;
      internalPort = 3969;
      responsePortStart = 40000;
      responsePortEnd = 40099;
    };

    power = {
      cpuGovernor = null;
      ups = {
        enable = false;
        mode = "standalone";
        name = "nas-ups";
        description = "NAS UPS";
        driver = "usbhid-ups";
        port = "auto";
        directives = [ ];
        passwordFile = "/etc/nixos/nixos-nas/secrets/nut-monitor-password";
        monitorUser = "nasmon";
        monitorSystem = "";
        serverListenAddresses = [ "127.0.0.1" "::1" ];
        web = {
          enable = true;
          allowControl = false;
          upsdAddress = "127.0.0.1";
          upsdPort = 3493;
        };
      };
    };

    virtualization = {
      enable = false;
      storagePath = "";
      runAsRoot = false;
      swtpm = true;
      virtiofs = true;
      allowedBridges = [ ];
    };

    secrets = {
      keepassDatabase = "/var/lib/nas-secrets/NAS.kdbx";
      keepassKeyFile = null;
      keepassGroup = "NixOS NAS";
    };

    alerting.enable = false;

    backup = {
      enable = false;
      repositoryFile = "/run/secrets/restic-repository";
      passwordFile = "/run/secrets/restic-password";
      allowSamePoolRepository = false;
      stagingPath = "/var/lib/nas-backup/staging";
      restoreVerification = {
        enable = true;
        onCalendar = "monthly";
        targetPath = "/var/lib/nas-backup/restore-verify";
      };
    };

    autoUpdate = {
      enable = true;
      onCalendar = "Mon 03:00";
      apply = false;
    };
  };
}
