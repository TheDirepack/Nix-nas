args:
let
  inherit (args)
    authentikApiTokenFile
    authentikBootstrapTokenFile
    authentikPort
    aiStorageRoot
    cfg
    copypartyUserConfigDir
    lib
    llamaCppPackage
    nasSecrets
    nasUpdate
    nasPreflight
    nasZfsCreateEncryptedDataset
    nasZfsMountCheck
    pkgs
    shareRoot
    syncthingConfigDir
    systemStateVersion
    vaultwardenBackupDir
  ;
  vaultwardenStateDirectory =
    if lib.versionOlder systemStateVersion "24.11" then "bitwarden_rs" else "vaultwarden";
  vaultwardenDataDir = "/var/lib/${vaultwardenStateDirectory}";

  nasPythonApplication = pkgs.python3Packages.buildPythonApplication {
    pname = "nixos-nas-control";
    version = lib.removeSuffix "\n" (builtins.readFile ../../../VERSION);
    pyproject = true;
    src = lib.cleanSource ../../..;
    build-system = [ pkgs.python3Packages.setuptools ];
    dependencies = with pkgs.python3Packages; [
      defusedxml
      jsonschema
      pyjwt
      pyyaml
      ruamel-yaml
    ];
    pythonImportsCheck = [
      "nas_ai_config"
      "nas_alert_router"
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
  nasAlertRouter = "${nasPythonApplication}/bin/nas-alert-router";
  nasIdentitySyncScript = "${nasPythonApplication}/bin/nas-identity-sync";
  nasIdentityPython = pkgs.python3;
  nasIdentitySync = pkgs.writeShellApplication {
    name = "nas-identity-sync";
    runtimeInputs = [ pkgs.coreutils pkgs.python3 pkgs.systemd ];
    text = ''
      export NAS_AUTHENTIK_URL=http://127.0.0.1:${toString authentikPort}${lib.removeSuffix "/" cfg.identity.authentikPath}
      export NAS_AUTHENTIK_TOKEN_FILE=${lib.escapeShellArg authentikApiTokenFile}
      export NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE="''${NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE:-${lib.escapeShellArg authentikBootstrapTokenFile}}"
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
      export NAS_ADMIN_USER=${lib.escapeShellArg cfg.adminUser}
      export NAS_KEEPASS_DATABASE=${lib.escapeShellArg cfg.secrets.keepassDatabase}
      export NAS_KEEPASS_KEY_FILE=${lib.escapeShellArg (if cfg.secrets.keepassKeyFile == null then "" else cfg.secrets.keepassKeyFile)}
      export NAS_ZFS_POOL=${lib.escapeShellArg cfg.zfsPool}
      export NAS_ZFS_DATASET=${lib.escapeShellArg cfg.zfsDataset}
      export NAS_ZFS_ROOT=${lib.escapeShellArg cfg.zfsRoot}
      export NAS_ZFS_ENCRYPTION_ENABLE=${if cfg.zfsEncryption.enable then "1" else "0"}
      export NAS_SHARE_ROOT=${lib.escapeShellArg shareRoot}
      export NAS_SYNCTHING_ENABLE=${if cfg.syncthing.enable then "1" else "0"}
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
  mkDatabaseAuthority = { name, source, sensitive ? true, optional ? false }: {
    inherit name source sensitive optional;
    kind = "database";
    restoreStrategy = "database-native";
    owner = null;
    group = null;
    rootMode = null;
  };

  # Ownership is an installation contract, not archive metadata. This lets
  # disaster recovery recreate an authority that does not yet exist without
  # guessing root:root ownership from the empty target host.
  stateRegistry = [
    (mkPathAuthority {
      name = "managed-services";
      source = "/var/lib/nas-control/services.yaml";
      owner = "root";
      group = "nas-operations";
      rootMode = "0640";
    })
    (mkPathAuthority {
      name = "first-run";
      source = "/var/lib/nas-setup";
      optional = true;
      group = "wheel";
      rootMode = "0750";
    })
    (mkPathAuthority {
      name = "copyparty";
      source = "/var/lib/copyparty";
      sensitive = true;
      owner = "copyparty";
      group = "copyparty";
      rootMode = "0750";
    })
    (mkPathAuthority {
      name = "identity-sync";
      source = "/var/lib/nas-identity-sync";
      sensitive = true;
      rootMode = "0700";
    })
    (mkPathAuthority {
      name = "caddy";
      source = "/var/lib/caddy";
      sensitive = true;
      owner = "caddy";
      group = "caddy";
      rootMode = "0700";
    })
    (mkPathAuthority {
      name = "authentik-media";
      source = "/var/lib/authentik/data";
      sensitive = true;
      owner = "authentik";
      group = "authentik";
      rootMode = "0750";
    })
    (mkPathAuthority {
      name = "keepass";
      source = cfg.secrets.keepassDatabase;
      sensitive = true;
      owner = cfg.adminUser;
      group = "users";
      rootMode = "0600";
    })
    (mkDatabaseAuthority { name = "authentik-database"; source = "postgresql://authentik"; })
  ]
  ++ lib.optionals cfg.networking.enable [
    (mkPathAuthority {
      name = "networkmanager";
      source = "/etc/NetworkManager/system-connections";
      sensitive = true;
      rootMode = "0700";
    })
  ]
  ++ lib.optionals (cfg.networking.enable && cfg.networking.firewall.enable) [
    (mkPathAuthority { name = "firewall"; source = "/var/lib/nas-firewall"; rootMode = "0700"; })
  ]
  ++ lib.optionals cfg.syncthing.enable [
    (mkPathAuthority {
      name = "syncthing";
      source = syncthingConfigDir;
      sensitive = true;
      owner = "syncthing";
      group = "copyparty";
      rootMode = "0700";
    })
  ]
  ++ lib.optionals (cfg.scheduler.backend == "cockpit-scheduler") [
    (mkPathAuthority { name = "scheduler"; source = "/var/lib/cockpit-scheduler"; optional = true; })
  ]
  ++ lib.optionals cfg.vaultwarden.enable [
    (mkPathAuthority {
      name = "vaultwarden";
      source = vaultwardenDataDir;
      sensitive = true;
      owner = "vaultwarden";
      group = "vaultwarden";
      rootMode = "0700";
    })
    (mkPathAuthority {
      name = "vaultwarden-backups";
      source = vaultwardenBackupDir;
      sensitive = true;
      optional = true;
      owner = "vaultwarden";
      group = "vaultwarden";
      rootMode = "0700";
    })
  ]
  ++ lib.optionals (cfg.observability.enable && cfg.observability.grafana.enable) [
    (mkPathAuthority {
      name = "grafana";
      source = "/var/lib/grafana";
      sensitive = true;
      owner = "grafana";
      group = "grafana";
      rootMode = "0700";
    })
  ]
  ++ lib.optionals (cfg.observability.enable && cfg.alerting.enable) [
    (mkPathAuthority {
      name = "alert-router";
      source = "/var/lib/nas-alert-router";
      owner = "nas-observability";
      group = "nas-observability";
      rootMode = "0700";
    })
  ]
  ++ lib.optionals cfg.observability.ntfy.enable [
    (mkPathAuthority {
      name = "ntfy";
      source = "/var/lib/ntfy-sh";
      sensitive = true;
      owner = "ntfy-sh";
      group = "ntfy-sh";
      rootMode = "0700";
    })
  ]
  ++ lib.optionals cfg.ai.enable [
    (mkPathAuthority {
      name = "llama-swap";
      source = "/var/lib/nas-llama-swap";
      owner = "nas-ai";
      group = "nas-ai";
      rootMode = "0750";
    })
    (mkPathAuthority {
      name = "open-webui";
      source = "/var/lib/open-webui";
      sensitive = true;
      owner = "open-webui";
      group = "open-webui";
      rootMode = "0700";
    })
  ]
  ++ lib.optionals (cfg.ai.enable && cfg.ai.codingAgent.enable) [
    (mkPathAuthority {
      name = "coding-agent";
      source = "/var/lib/nas-code-agent";
      sensitive = false;
      optional = true;
      owner = "nas-code-agent";
      group = "nas-code-agent";
      rootMode = "0750";
    })
  ]
  ++ lib.optionals (cfg.ai.enable && cfg.ai.modelDownloader.enable) [
    (mkPathAuthority {
      name = "model-downloader";
      source = "${aiStorageRoot}/downloader-config";
      sensitive = true;
      owner = "hfdownloader";
      group = "nas-ai-models";
      rootMode = "0750";
    })
  ]
  ++ lib.optionals cfg.virtualization.enable [
    (mkPathAuthority {
      name = "libvirt";
      source = "/var/lib/libvirt";
      sensitive = true;
      rootMode = "0750";
    })
  ];

  stateQuiesceUnits = [
    "authentik.service"
    "authentik-worker.service"
    "nas-v2-timer-identity-sync-0.timer"
    "copyparty.service"
    "caddy.service"
  ]
  ++ lib.optional cfg.syncthing.enable "syncthing.service"
  ++ lib.optional cfg.vaultwarden.enable "vaultwarden.service"
  ++ lib.optionals (cfg.observability.enable && cfg.observability.grafana.enable) [ "grafana.service" ]
  ++ lib.optional (cfg.observability.enable && cfg.alerting.enable) "nas-alert-router.service"
  ++ lib.optional cfg.observability.ntfy.enable "ntfy-sh.service"
  ++ lib.optionals cfg.ai.enable [ "nas-llama-swap.service" "open-webui.service" ]
  ++ lib.optional (cfg.ai.enable && cfg.ai.codingAgent.enable) "nas-ai-coding-sessions.target"
  ++ lib.optional (cfg.ai.enable && cfg.ai.modelDownloader.enable) "podman-hfdownloader.service"
  ++ lib.optional cfg.virtualization.enable "libvirtd.service";

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
      pkgs.postgresql
    ] ++ lib.optional cfg.networking.enable pkgs.networkmanager;
    text = ''
      export NAS_SETUP_STATE_ROOT=/var/lib/nas-setup
      export NAS_FIREWALL_STATE_ROOT=/var/lib/nas-firewall
      export NAS_NETWORKMANAGER_STATE_ROOT=/etc/NetworkManager/system-connections
      export NAS_COPYPARTY_STATE_ROOT=/var/lib/copyparty/user.d
      export NAS_SYNCTHING_STATE_PATH=${lib.escapeShellArg (syncthingConfigDir + "/config.xml")}
      export NAS_AUTHENTIK_STATE_ROOT=/var/lib/authentik/data
      export NAS_KEEPASS_DATABASE=${lib.escapeShellArg cfg.secrets.keepassDatabase}
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
    # Authentik's worker expects its built-in system/bootstrap blueprint below
    # the configured root. Preserve that package tree and layer the repository
    # blueprint into the same immutable runtime bundle.
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
      export NAS_ADMIN_USER=${lib.escapeShellArg cfg.adminUser}
      export NAS_ZFS_POOL=${lib.escapeShellArg cfg.zfsPool}
      export NAS_ZFS_DATASET=${lib.escapeShellArg cfg.zfsDataset}
      export NAS_CONFIG_DIR=${lib.escapeShellArg cfg.configurationDir}
      export NAS_IDENTITY_URL=${lib.escapeShellArg cfg.identity.authentikPath}
      export NAS_FIRST_RUN_CONFIG=${lib.escapeShellArg cfg.firstStart.configFile}
      export NAS_FIRST_START_STATUS=/var/lib/nas-first-start/status.json
      exec ${nasCockpitApiScript} "$@"
    '';
  };

in
{
  inherit
    nasPythonApplication nasAlertRouter nasIdentitySyncScript nasIdentityPython nasIdentitySync
    nasSetupScript nasSetup nasStateScript nasState nasDoctorScript nasDoctor nasPortalStatic nasAuthentikBlueprints
    nasCockpitApiScript nasCockpitApi
  ;
}
