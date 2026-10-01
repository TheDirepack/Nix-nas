args:
let
  inherit (args)
    authentikApiTokenFile
    authentikBootstrapTokenFile
    authentikPort
    cfg
    copypartyUserConfigDir
    lib
    nasSecrets
    nasUpdate
    nasPreflight
    nasZfsCreateEncryptedDataset
    nasZfsMountCheck
    pkgs
    shareRoot
    syncthingConfigDir
  ;

  nasPythonApplication = pkgs.python3Packages.buildPythonApplication {
    pname = "nixos-nas-control";
    version = lib.removeSuffix "\n" (builtins.readFile ../../../VERSION);
    pyproject = true;
    src = lib.cleanSource ../../..;
    build-system = [ pkgs.python3Packages.setuptools ];
    dependencies = with pkgs.python3Packages; [
      defusedxml
      jsonschema
      pyyaml
      ruamel-yaml
    ];
    pythonImportsCheck = [
      "nas_ai_config"
      "nas_cockpit_api"
      "nas_doctor"
      "nas_identity_sync"
      "nas_logging"
      "nas_setup"
      "nas_state"
      "nas_v2_backup"
      "nas_v2_control"
      "nas_v2_editor"
      "nas_v2_session"
    ];
    doCheck = false;
  };
  nasIdentitySyncScript = "${nasPythonApplication}/bin/nas-identity-sync";
  nasIdentityPython = pkgs.python3;
  nasIdentitySync = pkgs.writeShellApplication {
    name = "nas-identity-sync";
    runtimeInputs = [ pkgs.coreutils pkgs.python3 pkgs.systemd ];
    text = ''
      export NAS_AUTHENTIK_URL=http://127.0.0.1:${toString authentikPort}${lib.removeSuffix "/" cfg.identity.authentikPath}
      export NAS_AUTHENTIK_TOKEN_FILE=${lib.escapeShellArg authentikApiTokenFile}
      export NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE="''${NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE:-${lib.escapeShellArg authentikBootstrapTokenFile}}"
      export NAS_PUBLIC_HOST=${lib.escapeShellArg cfg.identity.publicHost}
      export NAS_SHARE_ROOT=${lib.escapeShellArg shareRoot}
      export NAS_SYNCTHING_ENABLE=${if cfg.syncthing.enable then "1" else "0"}
      export NAS_SYNCTHING_CONFIG_DIR=${lib.escapeShellArg syncthingConfigDir}
      exec ${nasIdentitySyncScript} "$@"
    '';
  };

  nasSetupScript = "${nasPythonApplication}/bin/nas-setup";
  nasSetup = pkgs.writeShellApplication {
    name = "nas-setup";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.keepassxc
      pkgs.python3
      pkgs.shadow
      pkgs.systemd
      pkgs.util-linux
      pkgs.zfs
      nasPythonApplication
      nasIdentitySync
      nasPreflight
      nasSecrets
      nasZfsCreateEncryptedDataset
      nasZfsMountCheck
    ];
    text = ''
      export PATH=/run/wrappers/bin:$PATH
      export NAS_KEEPASS_DATABASE=${lib.escapeShellArg cfg.secrets.keepassDatabase}
      export NAS_KEEPASS_KEY_FILE=${lib.escapeShellArg (if cfg.secrets.keepassKeyFile == null then "" else cfg.secrets.keepassKeyFile)}
      export NAS_ZFS_POOL=${lib.escapeShellArg cfg.zfsPool}
      export NAS_ZFS_DATASET=${lib.escapeShellArg cfg.zfsDataset}
      export NAS_ZFS_ROOT=${lib.escapeShellArg cfg.zfsRoot}
      export NAS_ZFS_ENCRYPTION_ENABLE=${if cfg.zfsEncryption.enable then "1" else "0"}
      export NAS_SHARE_ROOT=${lib.escapeShellArg shareRoot}
      export NAS_SYNCTHING_ENABLE=${if cfg.syncthing.enable then "1" else "0"}
      export NAS_PUBLIC_HOST=${lib.escapeShellArg cfg.identity.publicHost}
      export NAS_SETUP_STATE=/var/lib/nas-setup/state.json
      export NAS_SETUP_JOURNAL=/var/lib/nas-setup/first-run-journal.json
      export NAS_FIRST_START_STATUS=/var/lib/nas-first-start/status.json
      exec ${nasSetupScript} "$@"
    '';
  };

  mkPathAuthority = {
    name,
    source,
    sensitive ? false,
    optional ? false,
    owner ? "root",
    group ? "root",
    rootMode ? (if sensitive then "0700" else "0750"),
  }: {
    inherit name source sensitive optional owner group rootMode;
    kind = "path";
    restoreStrategy = "path-policy";
  };

  # State bundles are deliberately small: they move runtime-editable control
  # configuration, not application databases or user data. Restic/native dump
  # jobs and ZFS snapshots own those larger recovery domains.
  stateRegistry = [
    (mkPathAuthority {
      name = "managed-services";
      source = "/var/lib/nas-control/services.yaml";
      owner = "root";
      group = "nas-operations";
      rootMode = "0640";
    })
    (mkPathAuthority {
      name = "copyparty-config";
      source = copypartyUserConfigDir;
      sensitive = true;
      owner = "copyparty";
      group = "copyparty";
      rootMode = "0770";
    })
  ]
  ++ lib.optionals cfg.networking.enable [
    (mkPathAuthority {
      name = "networkmanager";
      source = "/etc/NetworkManager/system-connections";
      sensitive = true;
      rootMode = "0700";
    })
  ]
  ++ lib.optionals (cfg.scheduler.backend == "cockpit-scheduler") [
    (mkPathAuthority {
      name = "scheduler";
      source = "/var/lib/cockpit-scheduler";
      optional = true;
    })
  ];

  # Exporting these file authorities does not require stopping application
  # databases or user workloads. Restore still restarts the native owners that
  # consume the restored control configuration.
  stateQuiesceUnits = [ ];

  stateRestoreUnits = [
    "nas-protected-services.target"
    "nas-v2-timer-identity-sync-0.timer"
  ]
  ++ lib.optional cfg.networking.enable "NetworkManager.service"
  ++ lib.optional (cfg.networking.enable && cfg.networking.firewall.enable) "firewalld.service";

  stateRegistryFile = pkgs.writeText "nas-state-authorities.json" (builtins.toJSON stateRegistry);

  nasStateScript = "${nasPythonApplication}/bin/nas-state";
  nasState = pkgs.writeShellApplication {
    name = "nas-state";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.python3
      pkgs.systemd
      pkgs.util-linux
    ] ++ lib.optional cfg.networking.enable pkgs.networkmanager;
    text = ''
      export NAS_STATE_REGISTRY_FILE=${stateRegistryFile}
      export NAS_STATE_REGISTRY_REQUIRED=1
      export NAS_STATE_RUNTIME_ROOT=/run/nas-state
      export NAS_STATE_QUIESCE_UNITS_JSON=${lib.escapeShellArg (builtins.toJSON stateQuiesceUnits)}
      export NAS_STATE_RESTORE_UNITS_JSON=${lib.escapeShellArg (builtins.toJSON stateRestoreUnits)}
      export NAS_STATE_SCHEMA=${../../../schemas/state-bundle.schema.json}
      export NAS_STATE_SIGNING_KEY=/run/nas-secrets/state/bundle-signing-key
      export NAS_VERSION=${lib.escapeShellArg (lib.removeSuffix "\n" (builtins.readFile ../../../VERSION))}
      export NAS_SOURCE_REVISION=${lib.escapeShellArg (toString ../../..)}
      exec ${nasStateScript} "$@"
    '';
  };

  nasDoctorScript = "${nasPythonApplication}/bin/nas-doctor";
  nasDoctor = pkgs.writeShellApplication {
    name = "nas-doctor";
    runtimeInputs = [ pkgs.coreutils pkgs.python3 pkgs.systemd ];
    text = ''
      export NAS_V2_SPEC=/var/lib/nas-control/services.yaml
      export NAS_V2_SCHEMA=/etc/nas-control/managed-services-v3.schema.json
      export NAS_V2_PLATFORM=/etc/nas-control/platform-capabilities.json
      export NAS_V2_EFFECTIVE=/run/nas-control/effective.json
      export NAS_SETUP_STATE=/var/lib/nas-setup/state.json
      export NAS_SETUP_JOURNAL=/var/lib/nas-setup/first-run-journal.json
      export NAS_FIRST_START_STATUS=/var/lib/nas-first-start/status.json
      export NAS_STATE_REGISTRY_FILE=${stateRegistryFile}
      export NAS_STATE_REGISTRY_REQUIRED=1
      export NAS_VERSION_FILE=${../../../VERSION}
      exec ${nasDoctorScript} "$@"
    '';
  };

  nasPortalStatic = pkgs.runCommand "nas-portal-static" { } ''
    install -d "$out/share/nas-portal"
    install -m 0444 ${../../../web/portal/index.html} "$out/share/nas-portal/index.html"
    install -m 0444 ${../../../web/portal/setup.html} "$out/share/nas-portal/setup.html"
  '';

  nasAuthentikBlueprints = pkgs.runCommand "nas-authentik-blueprints" { } ''
    mkdir -p "$out/share/authentik/blueprints"
    cp -a ${pkgs.authentik.src}/blueprints/. "$out/share/authentik/blueprints/"
    chmod -R u+w "$out/share/authentik/blueprints"
    install -m 0444 ${../../../authentik/blueprints/nas-user-settings.yaml} \
      "$out/share/authentik/blueprints/nas-user-settings.yaml"
    install -m 0444 ${../../../authentik/blueprints/nas-setup.yaml} \
      "$out/share/authentik/blueprints/nas-setup.yaml"
  '';

  nasCockpitApiScript = "${nasPythonApplication}/bin/nas-cockpit-api";
  nasCockpitApi = pkgs.writeShellApplication {
    name = "nas-cockpit-api";
    runtimeInputs = [
      pkgs.coreutils pkgs.git pkgs.hostname pkgs.python3 pkgs.sanoid pkgs.systemd pkgs.zfs
      nasPythonApplication nasIdentitySync nasSetup nasUpdate
    ];
    text = ''
      export NAS_ZFS_POOL=${lib.escapeShellArg cfg.zfsPool}
      export NAS_ZFS_DATASET=${lib.escapeShellArg cfg.zfsDataset}
      export NAS_ZFS_ROOT=${lib.escapeShellArg cfg.zfsRoot}
      export NAS_CONFIG_DIR=${lib.escapeShellArg cfg.configurationDir}
      export NAS_IDENTITY_URL=${lib.escapeShellArg cfg.identity.authentikPath}
      export NAS_FIRST_RUN_CONFIG=${lib.escapeShellArg cfg.firstStart.configFile}
      export NAS_FIRST_START_STATUS=/var/lib/nas-first-start/status.json
      export NAS_PUBLIC_HOST=${lib.escapeShellArg cfg.identity.publicHost}
      export NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE=/run/nas-authentik/api-token
      export NAS_SETUP_BIN=${nasSetup}/bin/nas-setup
      exec ${nasCockpitApiScript} "$@"
    '';
  };

in
{
  inherit
    nasPythonApplication nasIdentitySyncScript nasIdentityPython nasIdentitySync
    nasSetupScript nasSetup nasStateScript nasState nasDoctorScript nasDoctor nasPortalStatic nasAuthentikBlueprints
    nasCockpitApiScript nasCockpitApi
  ;
}
