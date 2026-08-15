{ config, lib, pkgs, nasInternal, ... }:

let
  inherit (nasInternal)
    authentikPort
    authentikOutpostPort
    caddyForwardAuth
    caddyCapabilityAuth
    caddyOnDemandAuth
    caddyOnDemandTransport
    cfg
    cockpitPort
    copypartySsoProxy
    identityAdminGroup
    lanHost
    nasPortalStatic
    syncthingGuiPort
    vaultwardenProxy
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

      ${lib.optionalString cfg.vaultwarden.enable ''@vaultAdmin path /vault/admin /vault/admin/*''}
      @adminShare path /shares/admin /shares/admin/*

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

      redir /dav /dav/
      handle /dav/* {
        route {
          ${caddyForwardAuth}
          ${caddyCapabilityAuth "webdav"}
          uri strip_prefix /dav
          ${copypartySsoProxy}
        }
      }

      ${lib.optionalString cfg.ai.enable ''
      @aiApi path /ai/v1 /ai/v1/*
      handle @aiApi {
        ${caddyOnDemandAuth "aiRuntime" "ai-api"}
        uri strip_prefix /ai
        reverse_proxy 127.0.0.1:${toString cfg.ai.llamaSwap.port} {
          ${caddyOnDemandTransport}
        }
      }

      redir /ai/runtime /ai/runtime/
      @aiRuntime path /ai/runtime/*
      handle @aiRuntime {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "aiRuntime" "admin"}
          uri strip_prefix /ai/runtime
          reverse_proxy 127.0.0.1:${toString cfg.ai.llamaSwap.port} {
            header_up X-Forwarded-Prefix /ai/runtime
            ${caddyOnDemandTransport}
          }
        }
      }

      ${lib.optionalString cfg.ai.modelDownloader.enable ''
      redir /ai/models /ai/models/
      @aiModels path /ai/models/*
      handle @aiModels {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "aiDownloader" "admin"}
          header Referrer-Policy "same-origin"
          uri strip_prefix /ai/models
          reverse_proxy 127.0.0.1:${toString cfg.ai.modelDownloader.port} {
            header_up X-Forwarded-Prefix /ai/models
            ${caddyOnDemandTransport}
          }
        }
      }
      ''}

      redir /ai /ai/
      @aiWorkspace path /ai/*
      handle @aiWorkspace {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "aiWorkspace" "ai"}
          request_header Remote-Role user
          @aiAdministrator header_regexp Remote-Groups (?i)(^|[|,][[:space:]]*)${identityAdminGroup}([[:space:]]*[|,]|$)
          request_header @aiAdministrator Remote-Role admin
          uri strip_prefix /ai
          reverse_proxy 127.0.0.1:${toString cfg.ai.openWebuiPort} {
            header_up Remote-User {http.request.header.Remote-User}
            header_up Remote-Groups {http.request.header.Remote-Groups}
            header_up Remote-Name {http.request.header.Remote-Name}
            header_up Remote-Email {http.request.header.Remote-Email}
            header_up Remote-Role {http.request.header.Remote-Role}
            header_up X-Forwarded-Prefix /ai
            header_up X-Forwarded-Proto https
            ${caddyOnDemandTransport}
          }
        }
      }
      ''}

      ${lib.optionalString (cfg.ai.enable && cfg.ai.modelDownloader.enable) ''
      @hfdAbsoluteAssets {
        path /css/style.css /js/app.js
        header_regexp hfdAssetRef Referer ^https://${lanHost}/ai/models(/.*)?$
      }
      handle @hfdAbsoluteAssets {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "aiDownloader" "admin"}
          reverse_proxy 127.0.0.1:${toString cfg.ai.modelDownloader.port} {
            ${caddyOnDemandTransport}
          }
        }
      }
      @hfdAbsoluteWebSocket {
        path /api/ws
        header Origin https://${lanHost}
        header Connection *Upgrade*
        header Upgrade websocket
      }
      handle @hfdAbsoluteWebSocket {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "aiDownloader" "admin"}
          reverse_proxy 127.0.0.1:${toString cfg.ai.modelDownloader.port} {
            ${caddyOnDemandTransport}
          }
        }
      }
      @hfdAbsoluteApi {
        path /api/*
        header_regexp hfdApiRef Referer ^https://${lanHost}/ai/models(/.*)?$
      }
      handle @hfdAbsoluteApi {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "aiDownloader" "admin"}
          reverse_proxy 127.0.0.1:${toString cfg.ai.modelDownloader.port} {
            ${caddyOnDemandTransport}
          }
        }
      }
      ''}

      ${lib.optionalString (cfg.power.ups.enable && cfg.power.ups.web.enable) ''
      redir /ups /ups/
      handle /ups/* {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "upsWeb" "admin"}
          reverse_proxy 127.0.0.1:${toString cfg.power.ups.web.port} {
            header_down X-Frame-Options SAMEORIGIN
            ${caddyOnDemandTransport}
          }
        }
      }
      ''}

      ${lib.optionalString cfg.observability.enable ''
      ${lib.optionalString cfg.alerting.enable ''
      redir /alerts /alerts/
      handle /alerts/* {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "alerts" "admin"}
          reverse_proxy 127.0.0.1:${toString cfg.observability.alertRouterPort} {
            header_down X-Frame-Options SAMEORIGIN
            ${caddyOnDemandTransport}
          }
        }
      }
      ''}

      redir /victoriametrics /victoriametrics/vmui
      handle /victoriametrics/* {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "observability" "admin"}
          reverse_proxy 127.0.0.1:${toString cfg.observability.victoriaMetricsPort} {
            header_down X-Frame-Options SAMEORIGIN
            ${caddyOnDemandTransport}
          }
        }
      }

      ${lib.optionalString cfg.observability.grafana.enable ''
      redir /metrics /metrics/
      handle /metrics/* {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "grafana" "admin"}
          reverse_proxy 127.0.0.1:${toString cfg.observability.grafana.port} {
            header_up X-WEBAUTH-USER {http.request.header.Remote-User}
            header_up X-WEBAUTH-NAME {http.request.header.Remote-Name}
            header_up X-WEBAUTH-EMAIL {http.request.header.Remote-Email}
            header_up X-WEBAUTH-ROLE Admin
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Prefix /metrics
            header_down X-Frame-Options SAMEORIGIN
            ${caddyOnDemandTransport}
          }
        }
      }
      ''}
      ''}

      ${lib.optionalString cfg.observability.ntfy.enable ''
      redir /notifications /notifications/
      # Preserve native ntfy authentication for non-browser clients.
      handle /notifications/* {
        reverse_proxy 127.0.0.1:${toString cfg.observability.ntfy.port} {
          header_down X-Frame-Options SAMEORIGIN
        }
      }
      ''}

      @console path /console /console/*
      handle @console {
        ${caddyForwardAuth}
        reverse_proxy https://127.0.0.1:${toString cockpitPort} {
          header_up X-Forwarded-Proto https
          header_up X-Forwarded-For {remote_host}
          transport http {
            tls_insecure_skip_verify
          }
        }
      }

      handle /settings/syncthing {
        route {
          ${caddyForwardAuth}
          ${caddyCapabilityAuth "syncthing"}
          redir * ${cfg.identity.authentikPath}if/flow/nas-user-settings/
        }
      }
      redir /settings ${cfg.identity.authentikPath}if/user/
      redir /settings/ ${cfg.identity.authentikPath}if/user/

      ${lib.optionalString cfg.syncthing.enable ''
      redir /syncthing /syncthing/
      handle /syncthing/* {
        route {
          ${caddyForwardAuth}
          ${caddyOnDemandAuth "syncthing" "admin"}
          uri strip_prefix /syncthing
          reverse_proxy 127.0.0.1:${toString syncthingGuiPort} {
            header_up Host {upstream_hostport}
          }
        }
      }
      ''}

      ${lib.optionalString cfg.vaultwarden.enable ''
      redir /vault /vault/
      @vaultSso path /vault/identity/connect/oidc /vault/identity/connect/oidc/* /vault/identity/connect/oidc-signin
      handle /vault/* {
        route {
          handle @vaultAdmin {
            ${caddyForwardAuth}
            ${vaultwardenProxy}
          }
          handle @vaultSso {
            ${caddyForwardAuth}
            ${caddyCapabilityAuth "vault"}
            ${vaultwardenProxy}
          }
          handle {
            ${caddyForwardAuth}
            ${caddyCapabilityAuth "vault"}
            ${vaultwardenProxy}
          }
        }
      }
      ''}

      # Native share links enforce their own token policy.
      redir /share /share/
      handle /share/* {
        ${copypartySsoProxy}
      }

      @shares path /shares /shares/*
      handle @shares {
        route {
          handle @adminShare {
            ${caddyForwardAuth}
            ${copypartySsoProxy}
          }
          handle {
            ${caddyForwardAuth}
            ${caddyCapabilityAuth "files"}
            ${copypartySsoProxy}
          }
        }
      }

      handle {
        route {
          ${caddyForwardAuth}
          root * ${nasPortalStatic}/share/nas-portal
          rewrite * /index.html
          templates {
            # The portal template is immutable, but its service links are a
            # runtime projection owned by nas-managed-service.
            root /
          }
          file_server
        }
      }
    '';
  };
}
