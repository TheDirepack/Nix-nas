{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikDataDir
    bootstrapAuthentikDataDir
    bootstrapPostgresqlDataDir
    bootstrapRuntimeRoot
    bootstrapSecretsDir
    authentikEnvironmentFile
    authentikRuntimeEnvironmentFile
    authentikRuntimeApiTokenFile
    authentikApiTokenFile
    authentikPort
    authentikOutpostPort
    nasAuthentikBlueprints
    cockpitNasPlugin
    cockpitPort
    cockpitOauthPort
    cockpitZfsPlugin
    cfg
    copypartyDataDir
    copypartyUserConfigDir
    lanHost
    postgresqlDataDir
    syncthingConfigDir
    syncthingDataDir
    syncthingGuiPort
    vaultwardenBackupDir
    vaultwardenDataDir
    vaultwardenOidcAuthority
    vaultwardenOidcClientId
    vaultwardenPort
    vaultwardenSecretDir
  ;
  authentikConfig = pkgs.formats.yaml { };
  authentikSettings = authentikConfig.generate "authentik.yml" {
    postgresql = {
      host = "/run/postgresql";
      name = "authentik";
      user = "authentik";
    };
    listen = {
      http = "127.0.0.1:${toString authentikPort}";
      https = "";
      trusted_proxy_cidrs = [ "127.0.0.1/32" "::1/128" ];
    };
    web.path = cfg.identity.authentikPath;
    storage = {
      backend = "file";
      file.path = "${authentikDataDir}/data";
    };
    # Load the repository-owned NAS blueprint instead of Authentik's immutable
    # package directory, which is not writable by the service.
    blueprints_dir = "${nasAuthentikBlueprints}/share/authentik/blueprints";
    avatars = "initials";
    disable_update_check = true;
    disable_startup_analytics = true;
    error_reporting.enabled = false;
  };
  authentikEnvironment = {
    AUTHENTIK_ENV = "production";
    HOME = authentikDataDir;
  };
  authentikServiceConfig = {
    User = "authentik";
    Group = "authentik";
    UMask = "0027";
    WorkingDirectory = authentikDataDir;
    EnvironmentFile = [ authentikRuntimeEnvironmentFile ];
    NoNewPrivileges = true;
    PrivateTmp = true;
    ProtectHome = true;
    ProtectSystem = "strict";
    ReadWritePaths = [ authentikDataDir "/var/lib/authentik" ];
    Restart = "on-failure";
    RestartSec = "2s";
  };
  # cockpit's Python bridge dies on sd_bus_attach_event returning EINVAL
  # (libsystemd variant mismatch under Nix); upstream only tolerates EBUSY.
  # Tolerating EINVAL turns a fatal shared-session crash into a per-channel
  # error, keeping the Authentik-gated session alive.
  cockpitPatched = pkgs.cockpit.overrideAttrs (old: {
    postPatch =
      (old.postPatch or "")
      + ''
        substituteInPlace cockpit/channels/dbus.py \
          --replace-fail 'if err.errno != errno.EBUSY:' 'if err.errno not in (errno.EBUSY, errno.EINVAL):' || true
      '';
  });

  cockpitWebService = pkgs.writeShellScript "nas-cockpit-webservice" ''
    set -euo pipefail
    # Caddy + Authentik are the only authorization boundary for /console.
    # cockpit-ws itself accepts the trusted loopback proxy without its own
    # login; --local-session shares one privileged bridge for that proxy.
    # nixpkgs installs cockpit-bridge under bin/, unlike Fedora's libexec.
    exec ${cockpitPatched}/libexec/cockpit-ws \
      --address 127.0.0.1 \
      --port ${toString cockpitPort} \
      --no-tls \
      --local-session ${cockpitPatched}/bin/cockpit-bridge
  '';
  authentikProxyOutpost = pkgs.writeShellScript "nas-authentik-proxy-outpost" ''
    set -euo pipefail
    token="$(${pkgs.coreutils}/bin/cat ${authentikRuntimeApiTokenFile})"
    outpost="$(${pkgs.curl}/bin/curl --fail --silent --show-error \
      -H "Authorization: Bearer $token" \
      http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}api/v3/outposts/instances/?page_size=100 \
      | ${pkgs.jq}/bin/jq -er '.results[] | select(.managed == "goauthentik.io/outposts/embedded") | .pk')"
    outpost_token="$(${pkgs.curl}/bin/curl --fail --silent --show-error \
      -H "Authorization: Bearer $token" \
      "http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}api/v3/core/tokens/ak-outpost-$outpost-api/view_key/" \
      | ${pkgs.jq}/bin/jq -er '.key')"
    exec ${pkgs.util-linux}/bin/runuser --user authentik -- env \
      AUTHENTIK_HOST="http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}" \
      AUTHENTIK_HOST_BROWSER="https://${cfg.identity.publicHost}${cfg.identity.authentikPath}" \
      AUTHENTIK_TOKEN="$outpost_token" \
      AUTHENTIK_INSECURE=true \
      AUTHENTIK_LISTEN__HTTP="127.0.0.1:${toString authentikOutpostPort}" \
      ${pkgs.authentik-outposts.proxy}/bin/proxy
  '';
in
{
  config = {
    services.cockpit = {
      enable = true;
      port = cockpitPort;
      openFirewall = false;
      showBanner = false;
      plugins = [
        pkgs.cockpit-files
        pkgs.cockpit-podman
        cockpitZfsPlugin
        cockpitNasPlugin
      ]
      ++ lib.optional cfg.virtualization.enable pkgs.cockpit-machines
      ++ lib.optional (cfg.scheduler.backend == "cockpit-scheduler" && cfg.scheduler.package != null) cfg.scheduler.package;
      allowed-origins = [
        "https://${lanHost}"
        "https://${cfg.identity.publicHost}"
        "https://${lanHost}:${toString cockpitPort}"
      ];
      settings.WebService = {
        AllowUnencrypted = false;
        ProtocolHeader = "X-Forwarded-Proto";
        ForwardedForHeader = "X-Forwarded-For";
        UrlRoot = "/console";
        LoginTo = false;
        AllowMultiHost = false;
      };
    };

    systemd.services.nas-cockpit-sso = {
      description = "Cockpit web service behind the Caddy Authentik gate";
      wantedBy = [ "multi-user.target" ];
      after = [ "nas-first-start.service" ];
      requires = [ "nas-first-start.service" ];
      # The shared bridge runs unauthenticated-by-design behind the Caddy
      # Authentik gate; it needs a writable HOME for agent/ssh state.
      environment.HOME = "/var/lib/nas-cockpit-sso";
      serviceConfig = {
        ExecStart = cockpitWebService;
        # A crashed shared bridge must never degrade into a second login
        # prompt; restarting ws respawns the local session within seconds.
        Restart = "always";
        RestartSec = "2s";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        StateDirectory = "nas-cockpit-sso";
        StateDirectoryMode = "0700";
        ReadOnlyPaths = [ "/var/lib/nas-setup/state.json" ];
        ReadWritePaths = [ "/var/lib/nas-cockpit-sso" ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" ];
      };
    };
    systemd.services.nas-authentik-proxy-outpost = {
      description = "Dedicated Authentik proxy outpost";
      wantedBy = [ "multi-user.target" ];
      requires = [ "authentik.service" "nas-identity-bootstrap.service" ];
      after = [ "authentik.service" "nas-identity-bootstrap.service" ];
      unitConfig.ConditionPathExists = [ authentikRuntimeApiTokenFile ];
      serviceConfig = {
        ExecStart = authentikProxyOutpost;
        Restart = "on-failure";
        RestartSec = "2s";
        NoNewPrivileges = false;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadOnlyPaths = [ authentikRuntimeApiTokenFile ];
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" ];
      };
    };

    environment.etc."authentik/config.yml".source = authentikSettings;
    systemd.tmpfiles.rules = [
      "d ${bootstrapRuntimeRoot} 0755 root root -"
      "d ${bootstrapAuthentikDataDir} 0750 authentik authentik -"
      "d ${bootstrapAuthentikDataDir}/data 0750 authentik authentik -"
      "d ${bootstrapPostgresqlDataDir} 0700 postgres postgres -"
      "d ${bootstrapSecretsDir} 0700 admin users -"
      "d ${syncthingDataDir} 0700 syncthing copyparty -"
      "d ${syncthingConfigDir} 0700 syncthing copyparty -"
      "L+ /var/lib/syncthing - - - - ${syncthingDataDir}"
      "d ${vaultwardenDataDir} 0700 vaultwarden vaultwarden -"
      "d ${vaultwardenBackupDir} 0700 vaultwarden vaultwarden -"
      "L+ /var/lib/${if lib.versionOlder config.system.stateVersion "24.11" then "bitwarden_rs" else "vaultwarden"} - - - - ${vaultwardenDataDir}"
      "L+ /var/backup/vaultwarden - - - - ${vaultwardenBackupDir}"
      "d ${copypartyDataDir} 0750 copyparty copyparty -"
      "d ${copypartyDataDir}/shares 2770 copyparty copyparty -"
      "L+ /var/lib/copyparty - - - - ${copypartyDataDir}"
    ];

    services.postgresql = {
      enable = true;
      dataDir = postgresqlDataDir;
      ensureDatabases = [ "authentik" ];
      ensureUsers = [
        {
          name = "authentik";
          ensureDBOwnership = true;
        }
      ];
    };
    systemd.services.postgresql = {
      requires = [ "nas-bootstrap-runtime-select.service" ];
      after = [ "nas-bootstrap-runtime-select.service" ];
    };
    systemd.services.authentik-migrate = {
      description = "Migrate the Authentik database";
      requires = [ "postgresql.service" "nas-bootstrap-runtime-select.service" ];
      after = [ "postgresql.service" "nas-bootstrap-runtime-select.service" ];
      before = [ "authentik.service" "authentik-worker.service" ];
      unitConfig.RequiresMountsFor = [ ];
      environment = authentikEnvironment;
      serviceConfig = authentikServiceConfig // {
        Type = "oneshot";
        RuntimeDirectory = "authentik-migrate";
        RuntimeDirectoryMode = "0750";
        RemainAfterExit = true;
        Restart = "on-failure";
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p ${authentikDataDir}/data";
        ExecStart = "${pkgs.authentik}/bin/ak migrate";
      };
    };
    systemd.services.authentik-worker = {
      description = "Authentik background worker";
      requires = [ "authentik-migrate.service" "nas-bootstrap-runtime-select.service" ];
      after = [ "authentik-migrate.service" "nas-bootstrap-runtime-select.service" ];
      unitConfig.RequiresMountsFor = [ ];
      environment = authentikEnvironment;
      serviceConfig = authentikServiceConfig // {
        RuntimeDirectory = "authentik-worker";
        RuntimeDirectoryMode = "0750";
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p ${authentikDataDir}/data";
        ExecStart = "${pkgs.authentik}/bin/ak worker";
      };
    };
    systemd.services.authentik = {
      description = "Authentik identity provider";
      requires = [ "authentik-migrate.service" "authentik-worker.service" "nas-bootstrap-runtime-select.service" ];
      after = [ "authentik-migrate.service" "authentik-worker.service" "nas-bootstrap-runtime-select.service" ];
      unitConfig.RequiresMountsFor = [ ];
      environment = authentikEnvironment;
      serviceConfig = authentikServiceConfig // {
        RuntimeDirectory = "authentik-server";
        RuntimeDirectoryMode = "0750";
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p ${authentikDataDir}/data";
        ExecStart = "${pkgs.authentik}/bin/ak server";
        ExecStartPost = pkgs.writeShellScript "authentik-ready" ''
          exec ${pkgs.coreutils}/bin/timeout 90s ${pkgs.curl}/bin/curl \
            --fail --silent --show-error \
            --connect-timeout 1 --max-time 2 \
            --retry 90 --retry-delay 1 --retry-connrefused --retry-all-errors \
            http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}-/health/ready/
        '';
      };
    };

    services.copyparty = {
      enable = true;
      package = pkgs.copyparty.overridePythonAttrs (old: {
        dependencies = old.dependencies ++ lib.optional cfg.tftp.enable pkgs.python3Packages.partftpy;
      });
      openFilesLimit = 8192;
      settings = {
        i = "unix:660:copyparty:/run/copyparty/http.sock";
        hist = "/var/cache/copyparty";
        "dav-auth" = true;
        "vol-or-crash" = true;
        "no-robots" = true;
        "idp-h-usr" = "Remote-User";
        "idp-h-grp" = "Remote-Groups";
        "auth-ord" = "idp";
        usernames = true;
        rproxy = 1;
        # NixOS's Unix-socket proxy presents to CopyParty from its dedicated
        # loopback proxy namespace, not from 127.0.0.1 itself.
        "xff-src" = "127.8.0.0/16";
        dedup = true;
        e2dsa = true;
        e2ts = true;
        "re-maxage" = 300;
        shr = "/share";
        "shr-adm" = "@nas_admin";
        "idp-store" = 3;
      } // lib.optionalAttrs cfg.tftp.enable {
        tftp = cfg.tftp.internalPort;
        # The HTTP endpoint is intentionally Unix-socket-only. TFTP is a
        # separate UDP listener, so bind it to loopback explicitly instead of
        # inheriting the Unix socket and silently disabling TFTP.
        "tftp-i" = "127.0.0.1";
        "tftp-pr" = "${toString cfg.tftp.responsePortStart}-${toString cfg.tftp.responsePortEnd}";
      };
      globalExtraConfig = ''
        % ${copypartyUserConfigDir}
      '';
      accounts = { };
      groups = { };
      volumes = { };
    };

    services.syncthing = lib.mkIf cfg.syncthing.enable {
      enable = true;
      group = "copyparty";
      dataDir = syncthingDataDir;
      configDir = syncthingConfigDir;
      guiAddress = "127.0.0.1:${toString syncthingGuiPort}";
      openDefaultPorts = false;
      overrideDevices = false;
      overrideFolders = false;
      settings = {
        gui = {
          insecureAdminAccess = false;
          theme = "black";
        };
        options = {
          urAccepted = -1;
          localAnnounceEnabled = true;
          globalAnnounceEnabled = cfg.syncthing.internetDiscovery;
          relaysEnabled = cfg.syncthing.internetDiscovery;
          natEnabled = cfg.syncthing.internetDiscovery;
        };
      };
    };

    services.vaultwarden = lib.mkIf cfg.vaultwarden.enable {
      enable = true;
      dbBackend = "sqlite";
      backupDir = vaultwardenBackupDir;
      environmentFile = [ "${vaultwardenSecretDir}/environment" ];
      config = {
        DOMAIN = "https://${lanHost}/vault";
        ROCKET_ADDRESS = "127.0.0.1";
        ROCKET_PORT = vaultwardenPort;
        ENABLE_WEBSOCKET = true;
        SIGNUPS_ALLOWED = false;
        SIGNUPS_DOMAINS_WHITELIST = "";
        INVITATIONS_ALLOWED = true;
        SSO_ENABLED = true;
        SSO_ONLY = cfg.vaultwarden.ssoOnly;
        SSO_SIGNUPS_MATCH_EMAIL = true;
        SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION = false;
        SSO_AUTHORITY = vaultwardenOidcAuthority;
        SSO_CLIENT_ID = vaultwardenOidcClientId;
        SSO_SCOPES = "profile email groups offline_access";
        SSO_PKCE = true;
        SSO_AUTH_ONLY_NOT_SESSION = false;
        SSO_CLIENT_CACHE_EXPIRATION = 600;
        SHOW_PASSWORD_HINT = false;
        IP_HEADER = "X-Real-IP";
        IP_HEADER_TRUSTED_PROXIES = "local";
        LOG_LEVEL = "info";
      };
    };

    systemd.services.copyparty = {
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" ];
      unitConfig.RequiresMountsFor = [ cfg.zfsRoot copypartyDataDir ];
      serviceConfig = {
        StateDirectory = lib.mkForce "${cfg.zfsRoot}/copyparty";
        StateDirectoryMode = lib.mkForce "0750";
      };
    };
    systemd.services.syncthing = lib.mkIf cfg.syncthing.enable {
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" ];
      unitConfig.RequiresMountsFor = [ cfg.zfsRoot syncthingDataDir ];
    };
    systemd.services.vaultwarden = lib.mkIf cfg.vaultwarden.enable {
      requires = [ "nas-zfs-mount-guard.service" ];
      after = [ "nas-zfs-mount-guard.service" ];
      unitConfig.RequiresMountsFor = [ cfg.zfsRoot vaultwardenDataDir vaultwardenBackupDir ];
    };
  };

  config.systemd.services.nas-bootstrap-runtime-select = {
    description = "Select boot-root or ZFS identity runtime storage";
    before = [ "postgresql.service" "authentik-migrate.service" "authentik-worker.service" "authentik.service" ];
    wants = [ "nas-bootstrap-authentik-secrets.service" ];
    after = [ "nas-bootstrap-authentik-secrets.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = pkgs.writeShellScript "nas-bootstrap-runtime-select" ''
        set -euo pipefail
        if [[ -e /var/lib/nas-setup/operational-runtime-select || -e /var/lib/nas-setup/state.json ]]; then
          ${pkgs.util-linux}/bin/mountpoint --quiet -- ${lib.escapeShellArg cfg.zfsRoot}
          target=${lib.escapeShellArg cfg.zfsRoot}
          environment=${lib.escapeShellArg authentikEnvironmentFile}
          api_token=${lib.escapeShellArg authentikApiTokenFile}
        else
          target=${lib.escapeShellArg bootstrapRuntimeRoot}
          environment="$target/authentik/environment"
          api_token="$target/authentik/api-token"
        fi
        ${pkgs.coreutils}/bin/install -d -m 0750 -o authentik -g authentik "$target/authentik"
        ${pkgs.coreutils}/bin/install -d -m 0700 -o postgres -g postgres "$target/postgresql"
        ${pkgs.coreutils}/bin/install -d -m 0700 -o admin -g users "$target/nas-secrets"
        for name in authentik postgresql nas-secrets; do
          ${pkgs.coreutils}/bin/rm -rf -- "/var/lib/$name"
          ${pkgs.coreutils}/bin/ln -s "$target/$name" "/var/lib/$name"
        done
        ${pkgs.coreutils}/bin/install -d -m 0750 -o root -g authentik /run/nas-authentik
        ${pkgs.coreutils}/bin/rm -f -- ${lib.escapeShellArg authentikRuntimeEnvironmentFile}
        ${pkgs.coreutils}/bin/ln -s "$environment" ${lib.escapeShellArg authentikRuntimeEnvironmentFile}
        ${pkgs.coreutils}/bin/rm -f -- ${lib.escapeShellArg authentikRuntimeApiTokenFile}
        ${pkgs.coreutils}/bin/ln -s "$api_token" ${lib.escapeShellArg authentikRuntimeApiTokenFile}
      '';
      NoNewPrivileges = false;
    };
  };

  config.systemd.services.nas-bootstrap-authentik-secrets = {
    description = "Create the first-boot-only Authentik runtime secrets";
    unitConfig.ConditionPathExists = [
      "!/var/lib/nas-setup/operational-runtime-select"
      "!/var/lib/nas-setup/state.json"
    ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = pkgs.writeShellScript "nas-bootstrap-authentik-secrets" ''
        set -euo pipefail
        environment=${lib.escapeShellArg "${bootstrapAuthentikDataDir}/environment"}
        [[ -e "$environment" ]] && exit 0
        ${pkgs.coreutils}/bin/install -d -m 0750 -o authentik -g authentik ${lib.escapeShellArg bootstrapAuthentikDataDir}
        temporary="$(${pkgs.coreutils}/bin/mktemp ${lib.escapeShellArg "${bootstrapAuthentikDataDir}/environment.XXXXXX"})"
        token_file="$temporary.token"
        trap '${pkgs.coreutils}/bin/rm -f -- "$temporary" "$token_file"' EXIT
        {
          token="$(${pkgs.openssl}/bin/openssl rand -hex 32)"
          printf '%s\n' 'AUTHENTIK_SECRET_KEY='"$(${pkgs.openssl}/bin/openssl rand -hex 64)"
          printf '%s\n' 'AUTHENTIK_BOOTSTRAP_TOKEN='"$token"
          printf '%s\n' 'AUTHENTIK_BOOTSTRAP_PASSWORD=nas-admin-first-boot'
          printf '%s\n' 'AUTHENTIK_BOOTSTRAP_EMAIL=${cfg.identity.bootstrapEmail}'
        } > "$temporary"
        ${pkgs.coreutils}/bin/install -m 0640 -o root -g authentik "$temporary" "$environment"
        printf '%s' "$token" > "$token_file"
        ${pkgs.coreutils}/bin/install -m 0400 -o root -g root "$token_file" ${lib.escapeShellArg "${bootstrapAuthentikDataDir}/api-token"}
        unset token
      '';
      UMask = "0077";
    };
  };
}
