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

Successful first-start setup provisions and verifies a scoped runtime service-account token, stores it in KeePassXC, and retires the bootstrap authority. Routine post-setup token replacement is not required.

Run `sudo nas-secrets status` to inspect the runtime token warning. If recovery from an incomplete or older setup leaves the bootstrap token in use, create a scoped service-account token in Authentik and store it with `sudo nas-secrets set-authentik-token`. Activate secrets again with `sudo nas-secrets activate`, then run `sudo nas-secrets check-authentik-token` to confirm it differs from the bootstrap credential and `sudo nas-identity-sync verify-token` to verify runtime API access before retiring any remaining bootstrap credential. Enter secrets only at the commands' prompts; do not put them in arguments or environment variables. For interrupted first-start setup, follow [First start](first-run.md) and its journal recovery procedure before resuming.

CopyParty paths, ACLs, quotas, flags, and native share links do not belong in Authentik; configure them in CopyParty.
