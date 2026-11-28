# ADR-0001: Authentik-only browser access

## Status

Accepted. This document describes the implemented permissioned-socket design.

## Context

Authentik owns browser authentication, MFA, and application memberships. Local
PAM administrators, console access, SSH recovery keys, and hardware KVM provide
the recovery plane when Authentik or the protected stack is unavailable.

Cockpit needs a Unix host session to execute administrative work. The appliance
starts one shared privileged bridge using Cockpit's native `--local-session`
mode. Caddy's authentication and authorization checks protect access to it.

## Decision

- Network browser access to Cockpit passes through Caddy and Authentik. The
  bootstrap proxy and generated V2 route require `application.cockpit.admin`
  membership or `nas_admin` before connecting to Cockpit.
- Cockpit listens only on `/run/nas-cockpit-sso/ws.sock`, owned by root and the
  Caddy group with mode `0660`. It inherits this socket from systemd and may not
  bind TCP listeners. The packaged Cockpit TCP socket is disabled.
- `cockpit-ws --no-tls --local-session cockpit-bridge` runs the shared host
  session. It does not independently validate Authentik JWTs or create a
  different Unix account/session for each browser user. The permissioned Unix
  socket and Caddy are the authentication boundary.
- Caddy removes client-supplied identity headers, obtains identity from the
  Authentik outpost, and checks the route's capability on each HTTP request.
  V2 generates capabilities and routes but never assigns human memberships.
- A WebSocket upgrade is one HTTP request. Subsequent messages on the upgraded
  connection do not repeat forward authentication. Revoking a group, disabling
  an account, or ending its Authentik session does not by itself close an
  established Cockpit connection. There is no configured finite stream lifetime
  or per-user connection-revocation mechanism.
- Before setup completes, the bootstrap Authentik instance and authenticated
  setup wizard form the browser setup path. The `akadmin` password is randomly
  generated on first boot and obtained through the recovery plane. Setup
  verifies the chosen administrator before retiring bootstrap authority.
- After setup, locked boot serves Authentik sign-in (running on a per-boot key)
  and a `nas_admin`-gated `/unlock/` page whose backend feeds
  `nas-secrets activate-stdin`. It exposes no browser management endpoint;
  unlock restarts Authentik with its KeePass environment, which invalidates
  pre-unlock sessions. Recovery when that layer fails requires console,
  authorized SSH, or hardware KVM.

Implementation authority lives in `application-services.nix`,
`caddy-bootstrap.nix`, `caddy-helpers.nix`, the V2 cockpit seed, and
`nas_v2_caddy.py`. The behavioral Cockpit and Caddy tests cover their boundaries.

## Consequences

Browser users authenticate through Authentik without a second PAM login. All
users granted Cockpit access must be fully trusted appliance administrators:
they enter the same privileged host session. Authentik and Caddy record browser
access, but that does not give every backend command a separate Unix identity.

Immediate removal of established console access requires a recovery-plane
administrator to revoke the Authentik grants and sessions, then restart
`nas-cockpit-sso.service`. This disconnects every console user. Verify that new
access is denied; ending the transport does not undo work or necessarily stop
independently launched jobs. See [Accounts and access](../src/admin/accounts.md).

V2 routes served under paths on the management hostname share its browser
origin. Proxy capability checks and cross-origin response headers do not
isolate scripts by path. Applications sharing that origin must be trusted;
applications needing separate browser trust should use V2 hostname exposure.

The remaining revocation and origin boundaries are tracked in
[Known risks](known-risks.md). Caddy's [streaming documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming)
describes WebSocket tunneling, configuration-reload closure, and stream limits.

## Alternatives

A second PAM login would introduce another browser authentication authority.
A custom token-to-Unix-session launcher would add token validation and session
lifecycle responsibilities that the current implementation does not provide.
Neither is part of the implemented design.
