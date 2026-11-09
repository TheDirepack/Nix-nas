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

Successful first-start setup provisions the `nas-automation` service account with the `NAS automation` role, stores both its scoped API token and the embedded outpost token in KeePassXC, and retires the bootstrap authority. Routine post-setup token replacement is not required.

Run `sudo nas-secrets status` to inspect the runtime token warning. For interrupted first-start setup, follow [First start](first-run.md) and its journal recovery procedure before resuming. Keep bootstrap authority available until both runtime credentials and browser access have been recovered.

If the outpost token is missing, use the existing setup runtime-token handoff through an authorized recovery integration:

1. Run `nas-identity-sync bootstrap-runtime-token` under the configured operator's privileged setup authority. It assigns the `NAS automation` role, provisions the API token, and retrieves the embedded outpost token. Its JSON output contains secrets: capture it in process memory, never display or log it.
2. Pass the KeePass password, returned `token`, and returned `outpostToken` as three newline-terminated stdin lines to `nas-secrets set-authentik-runtime-stdin`. This stores both `authentik-api-token` and `authentik-outpost-token`; the API-only setter cannot repair a missing outpost credential. Deliver secrets through the trusted integration's stdin transport, never arguments, environment variables, or persistent JSON files.
3. Activate secrets again with `sudo nas-secrets activate`. Restart `nas-authentik-proxy-outpost.service` and verify a fresh browser sign-in through Caddy and Authentik to the protected console. A working existing session alone does not prove the outpost can restart without bootstrap credentials.
4. Run `sudo nas-secrets check-authentik-token` to confirm the API token differs from the bootstrap credential and `sudo nas-identity-sync verify-token` to check user/group read access. That read probe does not prove account-mutation permissions; confirm the service account retains the `NAS automation` role. Only after these checks and the browser check pass may the guarded setup recovery workflow retire bootstrap authority.

If the outpost credential is already intact and only the API token needs replacement, assign its service account the same `NAS automation` role and store the replacement with `sudo nas-secrets set-authentik-token`. Enter secrets only at the commands' prompts, activate secrets again, and perform the same permission and browser checks before retiring any remaining bootstrap authority.

CopyParty paths, ACLs, quotas, flags, and native share links do not belong in Authentik; configure them in CopyParty.
