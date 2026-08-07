{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikEnvironmentFile
    authentikPort
    cockpitNasPlugin
    cockpitPort
    cockpitZfsPlugin
    cfg
    copypartyUserConfigDir
    lanHost
    syncthingConfigDir
    syncthingDataDir
    syncthingGuiPort
    vaultwardenBackupDir
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
      http = [ "127.0.0.1:${toString authentikPort}" ];
      https = [ ];
      trusted_proxy_cidrs = [ "127.0.0.1/32" "::1/128" ];
    };
    web.path = cfg.identity.authentikPath;
    storage = {
      backend = "file";
      file.path = "/var/lib/authentik/data";
    };
    avatars = "initials";
    disable_update_check = true;
    disable_startup_analytics = true;
    error_reporting.enabled = false;
  };
  authentikEnvironment = {
    AUTHENTIK_ENV = "production";
    HOME = "/var/lib/authentik";
  };
  authentikServiceConfig = {
    User = "authentik";
    Group = "authentik";
    StateDirectory = "authentik";
    UMask = "0027";
    WorkingDirectory = "/var/lib/authentik";
    EnvironmentFile = [ authentikEnvironmentFile ];
    NoNewPrivileges = true;
    PrivateTmp = true;
    ProtectHome = true;
    ProtectSystem = "strict";
    ReadWritePaths = [ "/var/lib/authentik" ];
    Restart = "on-failure";
    RestartSec = "2s";
  };
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

    environment.etc."authentik/config.yml".source = authentikSettings;
    services.postgresql = {
      enable = true;
      ensureDatabases = [ "authentik" ];
      ensureUsers = [
        {
          name = "authentik";
          ensureDBOwnership = true;
        }
      ];
    };
    systemd.services.authentik-migrate = {
      description = "Migrate the Authentik database";
      requires = [ "postgresql.service" ];
      after = [ "postgresql.service" ];
      before = [ "authentik.service" "authentik-worker.service" ];
      environment = authentikEnvironment;
      serviceConfig = authentikServiceConfig // {
        Type = "oneshot";
        RuntimeDirectory = "authentik-migrate";
        RuntimeDirectoryMode = "0750";
        RemainAfterExit = true;
        Restart = "on-failure";
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p /var/lib/authentik/data";
        ExecStart = "${pkgs.authentik}/bin/ak migrate";
      };
    };
    systemd.services.authentik-worker = {
      description = "Authentik background worker";
      requires = [ "authentik-migrate.service" ];
      after = [ "authentik-migrate.service" ];
      environment = authentikEnvironment;
      serviceConfig = authentikServiceConfig // {
        RuntimeDirectory = "authentik-worker";
        RuntimeDirectoryMode = "0750";
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p /var/lib/authentik/data";
        ExecStart = "${pkgs.authentik}/bin/ak worker";
      };
    };
    systemd.services.authentik = {
      description = "Authentik identity provider";
      requires = [ "authentik-migrate.service" "authentik-worker.service" ];
      after = [ "authentik-migrate.service" "authentik-worker.service" ];
      environment = authentikEnvironment;
      serviceConfig = authentikServiceConfig // {
        RuntimeDirectory = "authentik-server";
        RuntimeDirectoryMode = "0750";
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p /var/lib/authentik/data";
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
      package = pkgs.copyparty;
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
        "xff-src" = "127.0.0.1/32";
        dedup = true;
        e2dsa = true;
        e2ts = true;
        "re-maxage" = 300;
        shr = "/share";
        "shr-adm" = "@nas_admin";
        "idp-store" = 3;
      } // lib.optionalAttrs cfg.tftp.enable {
        tftp = cfg.tftp.internalPort;
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
  };
}
