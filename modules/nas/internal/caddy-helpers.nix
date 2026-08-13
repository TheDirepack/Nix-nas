args:
let
  inherit (args) authentikPort cfg vaultwardenPort;
  caddyForwardAuth = ''
    request_header -Remote-User
    request_header -Remote-Groups
    request_header -Remote-Name
    request_header -Remote-Email
    request_header -Remote-Role
    request_header -X-Authentik-Username
    request_header -X-Authentik-Groups
    request_header -X-Authentik-Name
    request_header -X-Authentik-Email
    request_header -X-Authentik-Uid
    forward_auth 127.0.0.1:${toString authentikPort} {
      uri ${cfg.identity.authentikPath}outpost.goauthentik.io/auth/caddy
      copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Name X-Authentik-Email X-Authentik-Uid
    }
    @missingAuthentikIdentity not header X-Authentik-Username *
    respond @missingAuthentikIdentity 403
    request_header Remote-User {http.request.header.X-Authentik-Username}
    request_header Remote-Groups {http.request.header.X-Authentik-Groups}
    request_header Remote-Name {http.request.header.X-Authentik-Name}
    request_header Remote-Email {http.request.header.X-Authentik-Email}
    request_header Remote-UID {http.request.header.X-Authentik-Uid}
  '';
  caddyOnDemandTransport = ''
    transport http {
      # Allow idle on-demand backends to stop promptly.
      keepalive 5s
    }
  '';
  copypartySsoProxy = ''
    reverse_proxy unix//run/copyparty/http.sock
  '';
  vaultwardenProxy = ''
    reverse_proxy 127.0.0.1:${toString vaultwardenPort} {
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-Proto https
    }
  '';
in
{
  inherit
    caddyForwardAuth
    caddyOnDemandTransport
    copypartySsoProxy
    vaultwardenProxy
  ;
}
