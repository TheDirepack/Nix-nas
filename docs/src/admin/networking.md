# Networking and remote access

NetworkManager owns runtime network profiles. firewalld owns mutable nftables policy. NixOS seeds the initial trusted-interface configuration, after which normal network changes can be made through Cockpit/NetworkManager without maintaining a second NAS-specific network database.

Interfaces not listed in `nas.trustedInterfaces` remain fail-closed by default.

## Normal access

| Purpose | Address |
|---|---|
| Application landing page | `https://<nas-hostname>.local/` |
| Cockpit after unlock | `https://<nas-hostname>.local/console/` |
| Authentik | `https://<nas-hostname>.local/identity/` |
| CopyParty | `https://<nas-hostname>.local/shares/` |
| Native CopyParty share links | `https://<nas-hostname>.local/share/` |

## Locked-state recovery

Locked boot exposes no browser management endpoint. Use the local console, SSH with a provisioned recovery key, or hardware KVM to run `sudo nas-secrets activate`. After activation, use the normal Caddy route and Authentik login.

## Optional ports

Syncthing, NUT, TFTP, and other optional listeners are opened only when their feature and firewall policy require them. Use Cockpit Networking or `firewall-cmd` to inspect the effective runtime policy.

## Isolated applications sharing a container port

Two isolated OCI/Quadlet applications can both listen on container port `8080`,
but they need different host-side publication ports. In the existing V2 model,
`routes.web.target.port` is the endpoint Caddy connects to **on the host**, not
necessarily the container port. Set a matching TCP listener's `exposure.port`
to that host port and its `targetPort` to the container port:

```yaml
schemaVersion: 3
services:
  alpha:
    name: Alpha
    workload: {kind: daemon}
    runtime:
      type: oci
      image: docker.io/library/python:3-alpine
      command: [python, -m, http.server, "8080"]
    network: {mode: isolated, outboundDefault: deny}
    listeners:
      web:
        protocol: tcp
        exposure: {port: 18080}
        targetPort: 8080
        firewall: false
    routes:
      web:
        target: {type: http, host: 127.0.0.1, port: 18080}
        exposure: {type: hostname, hostnames: [alpha.example.test]}
        auth: {mode: identity}
```

Configure the application's native server to listen on `8080`; V2 does not
change its native listening port. For a second application, use a different
service ID, hostname, and host port (for example `beta`, `beta.example.test`,
and `18081`), retaining `targetPort: 8080`. Assign the appropriate
`application.<service>.access` group in Authentik as usual.

This produces one loopback-only mapping per app (`127.0.0.1:18080:8080/tcp`
and `127.0.0.1:18081:8080/tcp`). `firewall: false` avoids a direct LAN listener;
the route grants host-to-container access to the translated container port.
Without remapping, routes retain same-port publication.

Choose unused host ports explicitly; there is no automatic port allocator.
Validation rejects isolated route publications overlapping another V2 service's
declared listener or local route backend, including disabled declarations.
Save through the existing revision-checked editor so concurrent edits cannot
silently replace one another. Ports occupied by software outside V2 are not
discovered by offline validation; a runtime bind failure must be repaired by
choosing an unused port, not by widening the bind address or firewall rules.
