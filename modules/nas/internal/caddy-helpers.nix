args:
let
  inherit (args) authentikOutpostPort authentikPort capabilityRegistry cfg lanHost lib onDemandGateSocket vaultwardenPort;
  authentikOutpostPath =
    if authentikOutpostPort == authentikPort
    then "${cfg.identity.authentikPath}outpost.goauthentik.io/auth/caddy"
    else "/outpost.goauthentik.io/auth/caddy";
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
    forward_auth 127.0.0.1:${toString authentikOutpostPort} {
      uri ${authentikOutpostPath}
      header_down Location "^http://127.0.0.1:${toString authentikPort}${cfg.identity.authentikPath}(.*)$" "https://${lanHost}${cfg.identity.authentikPath}$1"
      copy_headers {
        X-Authentik-Username
        X-Authentik-Groups
        X-Authentik-Entitlements
        X-Authentik-Name
        X-Authentik-Email
        X-Authentik-Uid
        X-Authentik-Jwt
        X-Authentik-Meta-Jwks
        X-Authentik-Meta-Outpost
        X-Authentik-Meta-Provider
        X-Authentik-Meta-App
        X-Authentik-Meta-Version
      }
    }
    @missingAuthentikIdentity not header X-Authentik-Username *
    respond @missingAuthentikIdentity 403
    request_header Remote-User {http.request.header.X-Authentik-Username}
    request_header Remote-Groups {http.request.header.X-Authentik-Groups}
    request_header Remote-Name {http.request.header.X-Authentik-Name}
    request_header Remote-Email {http.request.header.X-Authentik-Email}
    request_header Remote-UID {http.request.header.X-Authentik-Uid}
  '';
  caddyOnDemandAuth = feature: scope: ''
    forward_auth unix/${onDemandGateSocket} {
      uri /authorize?feature=${feature}&scope=${scope}
      header_up Remote-User {http.request.header.X-Authentik-Username}
      header_up Remote-Groups {http.request.header.X-Authentik-Groups}
      header_up Remote-Name {http.request.header.X-Authentik-Name}
      header_up Remote-Email {http.request.header.X-Authentik-Email}
      header_up Remote-UID {http.request.header.X-Authentik-Uid}
      header_up Authorization {http.request.header.Authorization}
      header_up X-API-Key {http.request.header.X-API-Key}
    }
  '';
  caddyCapabilityAuth = capability:
    let
      entry = lib.attrByPath [ capability ]
        (throw "Unknown NAS capability referenced by a Caddy route: ${capability}")
        capabilityRegistry;
    in ''
    forward_auth unix/${onDemandGateSocket} {
      uri /authorize?scope=${entry.id}
      header_up Remote-User {http.request.header.X-Authentik-Username}
      header_up Remote-Groups {http.request.header.X-Authentik-Groups}
      header_up Remote-Name {http.request.header.X-Authentik-Name}
      header_up Remote-Email {http.request.header.X-Authentik-Email}
      header_up Remote-UID {http.request.header.X-Authentik-Uid}
    }
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
    caddyOnDemandAuth
    caddyCapabilityAuth
    caddyOnDemandTransport
    copypartySsoProxy
    vaultwardenProxy
  ;
}
