{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    cfg
    cockpitPort
    lanHost
    nasPortalStatic
    secretRoot
  ;
  activeCaddyPath = "/run/nas-control/caddy-active.conf";
  bootstrapCaddyfileGen = pkgs.writeText "bootstrap-caddyfile-gen.sh" ''
    #!/usr/bin/env bash
    set -euo pipefail
    NAS_PORTAL_STATIC=${nasPortalStatic}
    COCKPIT_PORT=${toString cockpitPort}
    LAN_HOST=${lanHost}
    SECRET_ROOT=${secretRoot}
    cat <<EOF
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

https://${LAN_HOST} {
  tls internal
  encode zstd gzip
  header {
    -Server
    X-Content-Type-Options "nosniff"
    Referrer-Policy "no-referrer"
    Permissions-Policy "camera=(), microphone=(), geolocation=()"
  }

  handle /console/* {
    reverse_proxy 127.0.0.1:${COCKPIT_PORT} {
      header_up X-Forwarded-Proto https
      header_up X-Forwarded-Prefix /console
    }
  }
  handle /console {
    reverse_proxy 127.0.0.1:${COCKPIT_PORT} {
      header_up X-Forwarded-Proto https
      header_up X-Forwarded-Prefix /console
    }
  }

  # Bootstrap landing: redirect root to setup. The setup form collects the
  # admin username + password that seeds the entire system (Caddy credentials,
  # Authentik admin, system password, KeePass encryption key). No auth is
  # required pre-secrets; the setup page is the only public surface until
  # first-run completes.
  handle_path / {
    redir /setup 303
  }

  # Serve the setup form at /setup.
  handle_path /setup {
    root * ${NAS_PORTAL_STATIC}/share/nas-portal
    file_server
  }
}
EOF
  '';
  bootstrapCaddyfile = pkgs.runCommand "bootstrap-caddyfile" {
    nativeBuildInputs = [ bootstrapCaddyfileGen ];
  } ''
    export NAS_PORTAL_STATIC=${nasPortalStatic}
    export COCKPIT_PORT=${toString cockpitPort}
    export LAN_HOST=${lanHost}
    export SECRET_ROOT=${secretRoot}
    ${bootstrapCaddyfileGen} > $out
  '';
  fullCaddyImport = "import /etc/caddy/caddy_config";
  caddyPackage = config.services.caddy.package;
  runOptions = "--config ${activeCaddyPath} --adapter caddyfile";
  renderActive = pkgs.writeShellScript "nas-caddy-bootstrap-select" ''
    set -euo pipefail
    if [[ -f ${secretRoot}/ready ]]; then
      # Secrets are active: ensure the V2 fragment is fresh before choosing the
      # full NixOS-generated configuration. Ordering against reconcile is
      # enforced here synchronously so Caddy never starts against a stale file.
      ${pkgs.systemd}/bin/systemctl start nas-managed-services-reconcile.service || true
      if [[ -f /run/nas-control/caddy-managed.conf ]]; then
        printf '%s\n' ${lib.escapeShellArg fullCaddyImport} > ${activeCaddyPath}
      else
        printf '%s\n' "import ${bootstrapCaddyfile}" > ${activeCaddyPath}
      fi
    else
      printf '%s\n' "import ${bootstrapCaddyfile}" > ${activeCaddyPath}
    fi
    # Reflect a selector change onto a running Caddy (secret activation at
    # runtime) without failing the first boot, when Caddy is still inactive.
    if ${pkgs.systemd}/bin/systemctl is-active --quiet caddy.service; then
      ${pkgs.systemd}/bin/systemctl reload caddy.service
    fi
  '';
in
{
  # The NixOS Caddy module bakes one configFile at eval time. The bootstrap /
  # full transition is a runtime decision (secret activation), so Caddy always
  # loads a /run-selected active file that imports either the Nix-rendered
  # bootstrap config or the module-generated full config.
  systemd.services.caddy.serviceConfig.ExecStart = lib.mkForce [
    ""
    "${caddyPackage}/bin/caddy run ${runOptions}"
  ];
  systemd.services.caddy.serviceConfig.ExecReload = lib.mkForce [
    ""
    "${caddyPackage}/bin/caddy reload ${runOptions} --force"
  ];
  # The module's reload triggers still reference the baked full config path so
  # NixOS activations keep reloading Caddy; our ExecReload re-reads the active
  # file, which imports the full config when secrets are active.

  systemd.services.nas-caddy-bootstrap = {
    description = "Select the active Caddy configuration (bootstrap vs full)";
    wantedBy = [ "multi-user.target" ];
    before = [ "caddy.service" ];
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
      PathChanged = "${secretRoot}/ready";
      Unit = "nas-caddy-bootstrap.service";
    };
  };
}