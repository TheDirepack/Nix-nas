# Authentik

Authentik is the authority for human identities, passwords, MFA, groups, profile fields, application/provider bindings, and user-editable Syncthing declarations.

## Administrator group

`nas_admin` is the only Authentik group with NAS superuser authority. Keep at least one enabled explicit member at all times. Add additional members only when they should be fully trusted appliance administrators.

## Application access

`nas_users` is a baseline identity group, not an access grant. In Authentik, explicitly assign only the V2 application capability groups a user needs. The default V2 seed declares these ordinary-user access groups:

- `application.copyparty.files`: CopyParty file access
- `application.copyparty.webdav`: WebDAV access
- `application.syncthing.access`: personal Syncthing declarations
- `application.vaultwarden.access`: Vaultwarden access

Capability groups are declared for every service in the V2 desired state, including a service that is currently disabled. Disabling a service removes its route from the generated proxy configuration and its Authentik application entry, but the capability group and its memberships remain, so re-enabling the service restores access without re-granting memberships. A service removed by a disabled Nix option is absent from the desired state and declares no group at all. To revoke access, remove the group memberships explicitly; disabling a service is not sufficient.

The seed also declares an administrator capability group for each application, such as `application.cockpit.admin` and `application.copyparty.admin`; [Account and permission model](../permissions.md) lists them. New services and new capabilities declare their own `application.<service>.<capability>` names. The retired `nas_allow_*` and `nas_deny_*` groups are not V2 authorization rules. Application bindings in Authentik should mirror the same capability groups so the dashboard matches the policy enforced by Caddy and the application backend.

Use [Accounts and access](accounts.md) for the guarded NAS account CLI and [Account and permission model](../permissions.md) for the full authorization model.

## Service token

The bootstrap token exists only to initialize Authentik. After bootstrap, create a narrower service-account token, store it with `nas-secrets set-authentik-token`, and verify it before removing the bootstrap credential. Cockpit warns while the normal API-token entry still contains the bootstrap value.

CopyParty paths, ACLs, quotas, flags, and native share links do not belong in Authentik; configure them in CopyParty.
