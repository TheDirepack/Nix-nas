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
    export PATH="${pkgs.procps}/bin:$PATH"
    # Caddy + Authentik are the only authorization boundary for /console.
    term() {
      [[ -n "''${WSPID:-}" ]] && kill -TERM "''${WSPID}" 2>/dev/null || true
      exit 0
    }
    trap term TERM INT
    while true; do
      ${cockpitPatched}/libexec/cockpit-ws \
        --address 127.0.0.1 \
        --port ${toString cockpitPort} \
        --no-tls \
        --local-session ${cockpitPatched}/bin/cockpit-bridge &
      WSPID=$!
      while kill -0 "$WSPID" 2>/dev/null; do
        sleep 2
        if ! pgrep -P "$WSPID" -f 'cockpit-bridge' >/dev/null 2>&1; then
          kill -TERM "$WSPID" 2>/dev/null || true
          break
        fi
      done
      wait "$WSPID" 2>/dev/null || true
      sleep 1
    done
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
      environment.HOME = "/var/lib/nas-cockpit-sso";
      serviceConfig = {
        ExecStart = cockpitWebService;
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

    environment.etc."authentik/config.yml".source = authentikSettings;
    systemd.tmpfiles.rules = [
      "d ${bootstrapRuntimeRoot} 0755 root root -"
      "d ${bootstrapAuthentikDataDir} 0750 authentik authentik -"
      "d ${bootstrapAuthentikDataDir}/data 0750 authentik authentik -"
      "d ${bootstrapPostgresqlDataDir} 0700 postgres postgres -"
      "d ${bootstrapSecretsDir} 0700 root root -"
      "d /var/lib/nas-operational 0700 root root -"
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
      environment = authentikEnvironment;
      serviceConfig = authentikServiceConfig // {
        ExecStart = "${pkgs.authentik}/bin/ak worker";
      };
    };
    systemd.services.authentik = {
      description = "Authentik server";
      wantedBy = [ "multi-user.target" ];
      requires = [ "authentik-migrate.service" "nas-bootstrap-runtime-select.service" ];
      after = [ "authentik-migrate.service" "nas-bootstrap-runtime-select.service" ];
      environment = authentikEnvironment;
      serviceConfig = authentikServiceConfig // {
        ExecStart = "${pkgs.authentik}/bin/ak server";
      };
    };
  };
}
