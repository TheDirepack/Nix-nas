# Authentik

Authentik is the authority for human identities, passwords, MFA, groups, profile fields, application/provider bindings, and user-editable Syncthing declarations.

## Administrator group

`nas_admin` is the only Authentik group with NAS superuser authority. Keep at least one enabled explicit member at all times. Add additional members only when they should be fully trusted appliance administrators.

## Application access

`nas_users` is a baseline identity group, not an access grant. In Authentik, explicitly assign only the V2 application capability groups a user needs. The default V2 seed declares:

- `application.copyparty.files` — CopyParty file access
- `application.copyparty.webdav` — WebDAV access
- `application.syncthing.access` — personal Syncthing declarations
- `application.vaultwarden.access` — Vaultwarden access

These groups exist only for enabled/deployed services. Other applications declare their own `application.<service>.<capability>` names. The retired `nas_allow_*` / `nas_deny_*` groups are not V2 authorization rules.

V2 creates the declared capability groups and launcher application bindings; **Authentik administrators own group membership assignments**. Caddy enforces the assigned capability (or `nas_admin`) at request time. Launcher filtering is not an authorization boundary, and application-native permissions still apply.

The guarded `nas-setup account` CLI manages reserved identity roles only. Use Authentik's directory/group UI—not `nas-setup account apply --group`—to grant application capabilities.

Use [Accounts and access](accounts.md) for the guarded NAS account CLI and [Account and permission model](../permissions.md) for the full authorization model.

## Service token

The bootstrap token exists only to initialize Authentik. After bootstrap, create a narrower service-account token, store it with `nas-secrets set-authentik-token`, and verify it before removing the bootstrap credential. Cockpit warns while the normal API-token entry still contains the bootstrap value.

CopyParty paths, ACLs, quotas, flags, and native share links do not belong in Authentik; configure them in CopyParty.
