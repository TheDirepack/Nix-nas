# Authentik

Authentik is the authority for human identities, passwords, MFA, groups, profile fields, application/provider bindings, and user-editable Syncthing declarations.

## Administrator group

`nas_admin` is the only Authentik group with NAS superuser authority. Keep at least one enabled explicit member at all times. Add additional members only when they should be fully trusted appliance administrators.

## Application access

`nas_users` is a baseline identity group, not an access grant. Give ordinary users only the capabilities they require:

- `nas_allow_files`
- `nas_allow_webdav`
- `nas_allow_syncthing`
- `nas_allow_vault`
- `nas_allow_ai`

Matching deny groups take precedence. Application bindings in Authentik should mirror the same capability groups so the dashboard matches the policy enforced by Caddy and the application backend.

Use [Accounts and access](accounts.md) for the guarded NAS account CLI and [Account and permission model](../permissions.md) for the full authorization model.

## Service token

The bootstrap token exists only to initialize Authentik. After bootstrap, create a narrower service-account token, store it with `nas-secrets set-authentik-token`, and verify it before removing the bootstrap credential. Cockpit warns while the normal API-token entry still contains the bootstrap value.

CopyParty paths, ACLs, quotas, flags, and native share links do not belong in Authentik; configure them in CopyParty.
