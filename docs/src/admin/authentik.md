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

If the outpost token is missing **and bootstrap authority is still retained**, use the existing setup runtime-token handoff through an authorized recovery integration. Keep out-of-band access available and do not reboot or start another setup/identity operation during this handoff:

1. Run `nas-identity-sync bootstrap-runtime-token` under the configured operator's privileged setup authority. It assigns the `NAS automation` role, provisions the API token, and retrieves the embedded outpost token. Its JSON output contains secrets: capture it in process memory, never display or log it.
2. Pass the KeePass password, returned `token`, and returned `outpostToken` as three newline-terminated stdin lines to `nas-secrets set-authentik-runtime-stdin`. This stores both `authentik-api-token` and `authentik-outpost-token`; the API-only setter cannot repair a missing outpost credential. Deliver secrets through the trusted integration's stdin transport, never arguments, environment variables, or persistent JSON files. Before restarting services or rebooting, also update the existing boot-side API-token file at `/var/lib/nas-control-plane/authentik/api-token` using the same root-only stdin handoff as `install_runtime_identity_token`: `install -m 0400 -o root -g root /dev/stdin /var/lib/nas-control-plane/authentik/api-token`. The trusted integration must pass only the new API token on stdin and use pre-authorized noninteractive privilege elevation so sudo cannot consume that input. Token provisioning rotates the key; leaving the old key in this file can break boot-side identity bootstrap or the outpost. If either write fails, stop the handoff and repair both copies before continuing.
3. Activate secrets again with `sudo nas-secrets activate`. Restart `nas-authentik-proxy-outpost.service` and verify a fresh browser sign-in through Caddy and Authentik to the protected console. A working existing session alone does not prove the outpost can restart without bootstrap credentials.
4. Run `sudo nas-secrets check-authentik-token` to confirm the API token differs from the bootstrap credential and `sudo nas-identity-sync verify-token` to check user/group read access. That read probe does not prove account-mutation permissions; confirm the service account retains the `NAS automation` role. Only after these checks and the browser check pass may the guarded setup recovery workflow retire bootstrap authority.

After successful setup has retired bootstrap authority, `bootstrap-runtime-token` is not a recovery command: its bootstrap credential no longer exists. Restore a valid matching KeePassXC backup containing both runtime credentials, using the [KeePassXC recovery procedure](../../operator/recovery.md#keepassxc-recovery); before its activation step, have the trusted integration synchronize the restored API token to the boot-side file through the step 2 stdin handoff, then perform steps 3 and 4. Do not restore revoked keys over newer valid credentials. If no usable credential backup exists, an authorized Authentik administrator must recover the embedded outpost credential and issue a runtime API token for a service account with the `NAS automation` role through Authentik's own management interface. Supply that pair to the trusted integration in step 2, including the boot-side file update, then perform steps 3 and 4. This path does not recreate bootstrap authority or retire already removed credentials. If no Authentik administrator remains accessible, restore matching Authentik and KeePassXC backups through the out-of-band recovery plane.

If the outpost credential is already intact and only the API token needs replacement, assign its service account the same `NAS automation` role and store the replacement with `sudo nas-secrets set-authentik-token`. Enter secrets only at the commands' prompts, update the boot-side API-token file through the step 2 stdin handoff, activate secrets again, and perform the same permission and browser checks before retiring any remaining bootstrap authority.

CopyParty paths, ACLs, quotas, flags, and native share links do not belong in Authentik; configure them in CopyParty.
