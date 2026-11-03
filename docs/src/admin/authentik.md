# Authentik

Authentik is the authority for human identities, passwords, MFA, groups, profile fields, application/provider bindings, and user-editable Syncthing declarations.

## Administrator group

`nas_admin` is the only Authentik group with NAS superuser authority. Keep at least one enabled explicit member at all times. Add additional members only when they should be fully trusted appliance administrators.

## Application access

`nas_users` is a baseline identity group, not an access grant. In Authentik, explicitly assign only the V2 application capability groups a user needs. The default V2 seed declares:

- `application.copyparty.files`: CopyParty file access
- `application.copyparty.webdav`: WebDAV access
- `application.syncthing.access`: personal Syncthing declarations
- `application.vaultwarden.access`: Vaultwarden access

These groups exist only for enabled or deployed services; other applications declare their own `application.<service>.<capability>` names. The retired `nas_allow_*` and `nas_deny_*` groups are not V2 authorization rules. Application bindings in Authentik should mirror the same capability groups so the dashboard matches the policy enforced by Caddy and the application backend.

Disabling an application binding removes its route, but the service's authorization group and existing memberships remain intact. Re-enabling the binding restores access without re-granting memberships. To revoke access, remove the group memberships explicitly; disabling alone is not sufficient.

Use [Accounts and access](accounts.md) for the guarded NAS account CLI and [Account and permission model](../permissions.md) for the full authorization model.

## Service token

The bootstrap token exists only to initialize Authentik. After bootstrap, create a narrower service-account token, store it with `nas-secrets set-authentik-token`, and verify it before removing the bootstrap credential. Cockpit warns while the normal API-token entry still contains the bootstrap value.

CopyParty paths, ACLs, quotas, flags, and native share links do not belong in Authentik; configure them in CopyParty.
