{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikPort
    caddyForwardAuth
    cfg
    cockpitPort
    firstRunWizardStatic
    lanHost
    nasPythonApplication
    nasSetup
    secretRoot
  ;
  authentikPathNoSlash = lib.removeSuffix "/" cfg.identity.authentikPath;
  activeCaddyPath = "/run/nas-control/caddy-active.conf";
  firstRunApiSocket = "/run/nas-first-run-api/api.sock";
  bootstrapCaddyfileGen = pkgs.writeShellScript "bootstrap-caddyfile-gen" ''
    cat <<EOCF
{
  log {
    output file ${config.services.caddy.logDir}/access.log {
      mode 0640
      roll_size 100MiB
      roll_keep 10
      roll_keep_for 720h
    }
    format json
  }
}

https://${lanHost} {
  tls internal
  encode zstd gzip
  header {
    -Server
    X-Content-Type-Options "nosniff"
    Referrer-Policy "no-referrer"
    Permissions-Policy "camera=(), microphone=(), geolocation=()"
  }

  handle / {
    redir * ${cfg.identity.authentikPath}if/user/ 303
  }
  # /setup without the slash would make the wizard's relative asset URLs
  # resolve against /, so canonicalise to /setup/ before serving.
  handle /setup {
    redir /setup /setup/ 308
  }
  handle /setup/api/* {
    route {
      ${caddyForwardAuth}
      uri strip_prefix /setup/api
      reverse_proxy unix/${firstRunApiSocket} {
        # The first-run API accepts identity only from this authenticated Caddy
        # path. caddyForwardAuth removed any client-supplied Remote-* headers.
        header_up Remote-User {http.request.header.Remote-User}
        header_up Remote-Groups {http.request.header.Remote-Groups}
      }
    }
  }
  handle /setup/* {
    route {
      ${caddyForwardAuth}
      uri strip_prefix /setup
      root * ${firstRunWizardStatic}/share/nas-portal-wizard
      file_server
    }
  }

  redir ${authentikPathNoSlash} ${cfg.identity.authentikPath}
  @authentikUi path ${cfg.identity.authentikPath}*
  handle @authentikUi {
    reverse_proxy 127.0.0.1:${toString authentikPort}
  }
  @authentikFlows path /flows/*
  handle @authentikFlows {
    uri replace /flows ${cfg.identity.authentikPath}flows
    reverse_proxy 127.0.0.1:${toString authentikPort}
  }
  @authentikOutpost path /outpost.goauthentik.io/*
  handle @authentikOutpost {
    uri replace /outpost.goauthentik.io ${cfg.identity.authentikPath}outpost.goauthentik.io
    reverse_proxy 127.0.0.1:${toString authentikPort} {
      header_up Host {http.request.host}
      header_up X-Forwarded-Proto https
    }
  }
  handle /console* {
    route {
      ${caddyForwardAuth}
      @missingCockpitAdmin not header_regexp Remote-Groups (?i)(^|[|,][[:space:]]*)nas_admin([[:space:]]*[|,]|$)
      respond @missingCockpitAdmin 403
      reverse_proxy 127.0.0.1:${toString cockpitPort} {
        header_up X-Forwarded-Proto https
        header_up X-Forwarded-Prefix /console
      }
    }
  }

  handle {
    redir * ${cfg.identity.authentikPath}if/user/ 303
  }
}
EOCF
  '';
  bootstrapCaddyfile = pkgs.runCommand "bootstrap-caddyfile" {
    nativeBuildInputs = [ bootstrapCaddyfileGen ];
  } ''
    ${bootstrapCaddyfileGen} > $out
  '';
  fullCaddyImport = "import /etc/caddy/caddy_config";
  caddyPackage = config.services.caddy.package;
  runOptions = "--config ${activeCaddyPath} --adapter caddyfile";
  renderActive = pkgs.writeShellScript "nas-caddy-bootstrap-select" ''
    set -euo pipefail
    if [[ -f ${secretRoot}/ready && -f /var/lib/nas-setup/state.json ]]; then
      ${pkgs.systemd}/bin/systemctl start --no-block nas-managed-services-reconcile.service || true
      if [[ -f /run/nas-control/caddy-managed.conf ]]; then
        printf '%s\n' ${lib.escapeShellArg fullCaddyImport} > ${activeCaddyPath}
      else
        printf '%s\n' "import ${bootstrapCaddyfile}" > ${activeCaddyPath}
      fi
    else
      printf '%s\n' "import ${bootstrapCaddyfile}" > ${activeCaddyPath}
    fi
    if ${pkgs.systemd}/bin/systemctl is-active --quiet caddy.service; then
      ${pkgs.systemd}/bin/systemctl reload caddy.service
    fi
  '';
in
{
  systemd.services.caddy.serviceConfig.ExecStart = lib.mkForce [
    ""
    "${caddyPackage}/bin/caddy run ${runOptions}"
  ];
  systemd.services.caddy.serviceConfig.ExecReload = lib.mkForce [
    ""
    "${caddyPackage}/bin/caddy reload ${runOptions} --force"
  ];
  systemd.services.caddy.requires = lib.mkIf (
    cfg.networking.firewall.enable
    && cfg.trustedInterfaces != [ ]
    && !cfg.testing.installationReadyFixture
  ) [ "nas-management-network-guard.service" ];
  systemd.services.caddy.after = lib.mkIf (
    cfg.networking.firewall.enable
    && cfg.trustedInterfaces != [ ]
    && !cfg.testing.installationReadyFixture
  ) [ "nas-management-network-guard.service" ];

  systemd.services.nas-first-run-api = {
    description = "Authenticated standalone first-run setup API";
    wantedBy = [ "multi-user.target" ];
    before = [ "caddy.service" ];
    serviceConfig = {
      Type = "simple";
      User = "root";
      Group = "caddy";
      RuntimeDirectory = "nas-first-run-api";
      RuntimeDirectoryMode = "0750";
      UMask = "0077";
      ExecStart = "${nasPythonApplication}/bin/nas-first-run-api --socket ${firstRunApiSocket}";
      Restart = "on-failure";
      RestartSec = "2s";
      NoNewPrivileges = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      RestrictAddressFamilies = [ "AF_UNIX" ];
      ReadWritePaths = [
        "/run/nas-first-run-api"
        "/run/nas-first-start"
        "/run/nas-operations"
        "/run/lock"
      ];
    };
    path = [
      pkgs.libpwquality
      pkgs.systemd
      nasSetup
    ];
  };

  systemd.services.nas-caddy-bootstrap = {
    description = "Select the active Caddy configuration (bootstrap vs full)";
    wantedBy = [ "multi-user.target" ];
    before = [ "caddy.service" ];
    after = [ "nas-first-run-api.service" ];
    wants = [ "nas-first-run-api.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = renderActive;
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ReadWritePaths = [ "/run/nas-control" ];
      UMask = "0022";
    };
  };

  systemd.paths.nas-caddy-bootstrap = {
    description = "Rebuild the active Caddy config when secret activation changes";
    wantedBy = [ "multi-user.target" ];
    pathConfig = {
      PathChanged = [ "${secretRoot}/ready" "/var/lib/nas-setup/state.json" ];
      Unit = "nas-caddy-bootstrap.service";
    };
  };
}
