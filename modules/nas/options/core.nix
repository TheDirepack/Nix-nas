{ lib, ... }:

{
  options.nas = {
    memoryProfile = lib.mkOption {
      type = lib.types.enum [ "performance" "balanced" "low-memory" ];
      default = "balanced";
      description = ''
        Resource profile for tunable NAS services. "balanced" preserves the
        Alpha.4 low-resource defaults, "performance" allows larger caches and
        faster telemetry, and "low-memory" trades some throughput/cache hit
        rate for a smaller resident working set. This does not impose a hard
        global memory limit and does not include ZFS ARC.
      '';
    };
    adminUser = lib.mkOption {
      type = lib.types.str;
      default = "admin";
      description = "Immutable Linux administrator identity used for NAS administration and Cockpit PAM. Application identities are managed in Authentik.";
    };
    adminPasswordHashFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Absolute path to a root-only Linux administrator password hash. Authentik manages application identities; KeePassXC does not alter the local PAM password.";
    };
    hostPolicy = {
      mutableLocalPasswords = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Allow runtime mutation of local Linux/PAM passwords. This is a host-wide NixOS policy and is disabled by default in the reusable module.";
      };
      directCockpitRecovery = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Expose Cockpit's direct TLS/PAM recovery listener on trusted LAN interfaces. When false, Cockpit listens only on loopback for reverse-proxy access.";
      };
    };
    installationReady = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enables strict hardware, SSH, network, and ZFS readiness assertions before installation.";
    };
    configurationDir = lib.mkOption {
      type = lib.types.str;
      default = "/etc/nixos/nixos-nas";
      description = "Root-owned configuration tree used by nas-preflight and nas-update.";
    };
    firstStart = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Automatically publish first-start state at boot and expose the resumable setup workflow in Cockpit until setup is complete.";
      };
      configFile = lib.mkOption {
        type = lib.types.str;
        default = "/etc/nixos/nixos-nas/first-run.json";
        description = "Root-owned first-run JSON consumed by the automatic first-start service and Cockpit setup workflow.";
      };
    };
    trustedInterfaces = lib.mkOption {
      type = lib.types.listOf (lib.types.strMatching "^[A-Za-z0-9_.:-]+$");
      default = [ ];
      description = "LAN interfaces allowed to reach SSH, HTTPS, mDNS, Syncthing, and optional TFTP. Empty is fail-closed.";
    };
    identity = {
      authentikPath = lib.mkOption {
        type = lib.types.strMatching "^/[A-Za-z0-9._/-]*/$";
        default = "/identity/";
        description = "Public subpath where Authentik is served. It must begin and end with a slash.";
      };
      authentikOutpostPort = lib.mkOption {
        type = lib.types.port;
        default = 9000;
        description = "Loopback port used by the Authentik outpost. The default is Authentik's embedded listener; VM fixtures may select a standalone proxy listener.";
      };
      bootstrapEmail = lib.mkOption {
        type = lib.types.strMatching "^[^[:space:]@]+@[^[:space:]@]+$";
        default = "admin@nas.local";
        description = "Email used only when Authentik initially creates akadmin. Changing it later does not rename the existing account.";
      };
      userGroup = lib.mkOption {
        type = lib.types.str;
        default = "nas_users";
        description = "Baseline Authentik human-user group. It grants no NAS application permissions; use explicit nas_allow_* groups.";
      };
      guestGroup = lib.mkOption {
        type = lib.types.str;
        default = "nas_guests";
        description = "Authentik group used for restricted guest identities.";
      };
      disabledGroup = lib.mkOption {
        type = lib.types.str;
        default = "nas_disabled";
        description = "Authentik group whose members are denied NAS application access; CopyParty applies its own native ACL policy.";
      };
      syncInterval = lib.mkOption {
        type = lib.types.str;
        default = "5min";
        description = "How often the reserved Authentik identity model is validated and Authentik-owned Syncthing device declarations are reconciled.";
      };
    };
    secrets = {
      keepassDatabase = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/nas-secrets/NAS.kdbx";
        description = "KeePassXC database containing machine secrets. The database password is entered interactively and is never persisted by this project.";
      };
      keepassKeyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Optional KeePassXC database key-file path. The database password is still entered interactively.";
      };
      keepassGroup = lib.mkOption {
        type = lib.types.str;
        default = "NixOS NAS";
        description = "KeePassXC group containing appliance secret entries.";
      };
    };

    testing.installationReadyFixture = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      visible = false;
      description = "CI-only switch proving installation-ready assertions with synthetic hardware.";
    };
    testing.readOnlyPackageSet = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      visible = false;
      description = "CI-only switch for test frameworks that provide an immutable package set.";
    };

    desktop.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable an optional local XFCE session for maintenance or graphical KeePassXC editing. Secret activation itself uses keepassxc-cli and does not require a desktop session.";
    };
  };
}
