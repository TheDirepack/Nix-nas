{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikPort
    caddyForwardAuth
    caddyOnDemandTransport
    cfg
    lanHost
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
      # behind a non-cyclic V2 bootstrap boundary. The embedded outpost is
      # served by the same Authentik listener under the configured prefix.
      @authentikOutpost path /outpost.goauthentik.io/*
      handle @authentikOutpost {
        uri replace /outpost.goauthentik.io ${cfg.identity.authentikPath}outpost.goauthentik.io
        reverse_proxy 127.0.0.1:${toString authentikPort} {
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
      @authentikFlows path /flows/*
      handle @authentikFlows {
        uri replace /flows ${cfg.identity.authentikPath}flows
        reverse_proxy 127.0.0.1:${toString authentikPort} {
          header_up Host {http.request.host}
          header_up X-Forwarded-Proto https
          header_up X-Forwarded-For {remote_host}
        }
      }
      # V2 owns all application routes; no app-specific Caddy redirects are needed.
      # Trailing-slash canonicalization and route handling are defined in the V2
      # seed (managed-services-seed-v2.nix) and applied via generic Caddy primitives.

      # V2 application routes handle prefix stripping, headers, and lifecycle
      # without app-specific Caddy branches.
      handle /settings/syncthing {
        route {
          ${caddyForwardAuth}
          @missingSyncthingSettingsAccess {
            not header_regexp Remote-Groups (?i)(^|[|,][[:space:]]*)application\.syncthing\.admin([[:space:]]*[|,]|$)
          }
          respond @missingSyncthingSettingsAccess 403
          redir * ${cfg.identity.authentikPath}if/flow/nas-user-settings/
        }
      }
      redir /settings* ${cfg.identity.authentikPath}if/user/

      # Authentik owns the appliance home page and application launcher.
      handle {
        redir * ${cfg.identity.authentikPath}if/user/ 303
      }
    '';
  };
}
