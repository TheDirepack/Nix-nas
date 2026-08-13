{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikPort
    authentikOutpostPort
    caddyForwardAuth
    caddyOnDemandTransport
    cfg
    lanHost
    nasPortalStatic
  ;
  authentikPathNoSlash = lib.removeSuffix "/" cfg.identity.authentikPath;
in
{
  config.services.caddy = {
    enable = true;
    openFirewall = false;
    logFormat = ''format json'';
    virtualHosts.${lanHost}.extraConfig = ''
      tls internal
      encode zstd gzip
      header {
        -Server
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
      }

      # Recreate identity headers only from Authentik forward-auth.
      request_header -Remote-User
      request_header -Remote-Groups
      request_header -Remote-Name
      request_header -Remote-Email
      request_header -Remote-Role
      request_header -X-Authentik-Username
      request_header -X-Authentik-Groups
      request_header -X-Authentik-Name
      request_header -X-Authentik-Email

      log {
        output file ${config.services.caddy.logDir}/access.log {
          mode 0640
          roll_size 100MiB
          roll_keep 10
          roll_keep_for 720h
        }
        format json
      }

      # Authentik bootstrap/global routes remain static until Caddy itself moves
      # behind a non-cyclic V2 bootstrap boundary.
      @authentikOutpost path /outpost.goauthentik.io/*
      handle @authentikOutpost {
        reverse_proxy 127.0.0.1:${toString authentikOutpostPort} {
          ${lib.optionalString (authentikOutpostPort == authentikPort) ''uri replace /outpost.goauthentik.io ${cfg.identity.authentikPath}outpost.goauthentik.io''}
          header_up Host {http.request.host}
          header_up X-Forwarded-Proto https
          header_up X-Forwarded-For {remote_host}
          header_down Location "^http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}(.*)$" "https://${lanHost}${cfg.identity.authentikPath}$1"
        }
      }
      redir ${authentikPathNoSlash} ${cfg.identity.authentikPath}
      @authentikUi path ${cfg.identity.authentikPath}*
      handle @authentikUi {
        reverse_proxy 127.0.0.1:${toString authentikPort} {
          header_up Host {http.request.host}
          header_up X-Forwarded-Proto https
          header_up X-Forwarded-For {remote_host}
        }
      }

      # These are only URL-canonicalization redirects. The corresponding reverse
      # proxies, authorization, readiness, and on-demand lifecycle are V2-owned.
      ${lib.optionalString cfg.ai.enable ''
      redir /ai/runtime /ai/runtime/
      ${lib.optionalString cfg.ai.modelDownloader.enable ''
      redir /ai/models /ai/models/
      ''}
      ''}
      ${lib.optionalString (cfg.observability.enable && cfg.alerting.enable) ''
      redir /alerts /alerts/
      ''}
      ${lib.optionalString cfg.observability.enable ''
      redir /victoriametrics /victoriametrics/vmui
      ${lib.optionalString cfg.observability.grafana.enable ''
      redir /metrics /metrics/
      ''}
      ''}
      ${lib.optionalString cfg.observability.ntfy.enable ''
      redir /notifications /notifications/
      ''}
      ${lib.optionalString (cfg.power.ups.enable && cfg.power.ups.web.enable) ''
      redir /ups /ups/
      ''}

      # V2 now owns all application routes including Open WebUI, downloader
      # compatibility, and Syncthing. Generic primitives cover prefix stripping,
      # headers, and header constraints without app-specific Caddy branches.
      handle /settings/syncthing {
        route {
          ${caddyForwardAuth}
          @missingSyncthingSettingsAccess {
            not header_regexp Remote-Groups (?i)(^|[|,][[:space:]]*)application\.syncthing\.admin([[:space:]]*[|,]|$)
          }
          respond @missingSyncthingSettingsAccess 403
          redir ${cfg.identity.authentikPath}if/flow/nas-user-settings/
        }
      }
      redir /settings ${cfg.identity.authentikPath}if/user/
      redir /settings/ ${cfg.identity.authentikPath}if/user/

      # V2 application routes are imported before this bootstrap/fallback block.
      handle {
        route {
          ${caddyForwardAuth}
          root * ${nasPortalStatic}/share/nas-portal
          rewrite * /index.html
          templates
          file_server
        }
      }
    '';
  };
}
