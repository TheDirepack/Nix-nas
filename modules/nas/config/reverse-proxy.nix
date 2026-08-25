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
  firstRunApiSocket = "/run/nas-first-run-api/api.sock";
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

      # Recreate the complete trusted identity corpus only after Authentik.
      request_header -Remote-User
      request_header -Remote-Groups
      request_header -Remote-Name
      request_header -Remote-Email
      request_header -Remote-Role
      request_header -Remote-UID
      request_header -X-Authentik-Username
      request_header -X-Authentik-Groups
      request_header -X-Authentik-Entitlements
      request_header -X-Authentik-Name
      request_header -X-Authentik-Email
      request_header -X-Authentik-Uid
      request_header -X-Authentik-Jwt
      request_header -X-Authentik-Meta-Jwks
      request_header -X-Authentik-Meta-Outpost
      request_header -X-Authentik-Meta-Provider
      request_header -X-Authentik-Meta-App
      request_header -X-Authentik-Meta-Version
      request_header -X-Authentik-Meta-User
      request_header -X-Authentik-Meta-Is-Superuser
      request_header -X-Authentik-Role

      log {
        output file ${config.services.caddy.logDir}/access.log {
          mode 0640
          roll_size 100MiB
          roll_keep 10
          roll_keep_for 720h
        }
        format json
      }

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

      # A setup page already loaded in the browser must be able to observe the
      # final job result and request its one reboot after Caddy switches to the
      # permanent configuration. The API itself requires the random per-job
      # capability; no setup submission or password endpoint is exposed here.
      handle /setup/api/first-start/job/* {
        uri strip_prefix /setup/api
        reverse_proxy unix/${firstRunApiSocket}
      }
      handle /setup/api/reboot {
        uri strip_prefix /setup/api
        reverse_proxy unix/${firstRunApiSocket}
      }

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

      handle {
        redir * ${cfg.identity.authentikPath}if/user/ 303
      }
    '';
  };
}
