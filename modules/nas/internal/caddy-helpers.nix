args:
let
  inherit (args) authentikPort authentikOutpostPath cfg lanHost vaultwardenPort;
  caddyForwardAuth = ''
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
    forward_auth 127.0.0.1:${toString authentikPort} {
      uri ${authentikOutpostPath}
      header_up X-Forwarded-Proto {scheme}
      header_up X-Forwarded-Host {http.request.hostport}
      header_up X-Forwarded-Uri {uri}
      header_up X-Original-URL {http.request.scheme}://{http.request.hostport}{http.request.orig_uri}
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
