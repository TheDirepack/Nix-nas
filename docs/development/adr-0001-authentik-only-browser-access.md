# ADR-0001: Authentik-only browser access

## Status

Accepted

## Context

The appliance requires Authentik to be the sole browser authentication authority,
including for management functions. The existing first-boot design proxies Cockpit
through Caddy at `/console`; Cockpit then creates a separate local PAM session.

Authentik forward-auth can control access to Cockpit but cannot create Cockpit's
required Unix session. Cockpit's OAuth support uses an implicit flow and requires a
Bearer authentication command to verify the token before starting its bridge.

The old design also exposed Cockpit as browser-based recovery while Authentik and
Caddy were unavailable during locked boot. That conflicts with a literal
Authentik-only browser-login requirement.

## Decision

- Authentik is the sole authentication authority for every network-reachable browser
  route that reaches management or an application.
- Cockpit remains browser-accessible only through Caddy. Caddy must enforce the
  Authentik Cockpit administrator capability before proxying any request.
- Cockpit runs its normal loopback-only web service. Its Bearer authentication
  command verifies a short-lived Authentik OAuth token against Authentik's JWKS,
  requires the `nas_admin` claim, and only then starts the privileged bridge.
  It does not accept forward-auth headers or present a second browser login form.
- Locked-boot recovery is out of band only: local console, SSH with an explicitly
  provisioned recovery key, or hardware KVM. No HTTPS recovery UI is exposed while
  Authentik is unavailable.
- The initial browser bootstrap may serve static setup guidance only. It cannot
  authenticate a user, unlock secrets, create a Cockpit session, or reach a protected
  application. Operators complete first start from the out-of-band recovery plane.
- A later locked boot has the same out-of-band recovery requirement; static guidance
  is not a recovery UI.
- First boot uses Authentik's fixed bootstrap username `akadmin` with the
  documented temporary password `nas-admin-first-boot`. Setup retires that
  identity after it verifies the chosen administrator.

## Consequences

### Positive

- Browser users authenticate once through Authentik, including MFA and session
  revocation policy.
- No fixed Cockpit credentials or forwarded identity-header bypass is introduced.
- Caddy authorizes every Cockpit browser request before it can reach Cockpit, and
  Cockpit independently verifies the Authentik OAuth token and `nas_admin` claim.

### Negative

- Operators lose browser-based recovery during locked boot.
- Console, SSH, or KVM recovery must be documented and qualified on real hardware
  and in QEMU.
- All Authentik Cockpit administrators share the privileged Cockpit host session;
  Authentik and Caddy logs provide the browser access audit trail.

### Neutral

- Local PAM accounts remain a recovery authority, but never a network browser login
  authority.
- Earlier bootstrap plans that described `/console` as an HTTPS recovery surface are superseded.

## Alternatives considered

### Authentik-gated Cockpit with local PAM login

- **Pros:** Preserves the current Cockpit recovery workflow.
- **Cons:** Requires a second browser login and does not meet the requirement.
- **Why rejected:** It prompts for a second browser credential after Authentik.

### Custom Authentik token-to-Cockpit session bridge

- **Pros:** Could theoretically retain Cockpit with one browser login.
- **Cons:** Requires a privileged custom authentication launcher, token validation,
  subject-to-Unix-user mapping, and session lifecycle implementation.
- **Decision:** Required. Cockpit documents this as its supported Bearer
  authentication extension point. The implementation validates Authentik's
  signed token and never trusts a proxy header or disables Cockpit authentication.
