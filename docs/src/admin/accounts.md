# Accounts and access

Authentik is the authority for human accounts, passwords, MFA, and group membership. Use the Authentik UI for ordinary administration. The `nas-setup account` commands provide a guarded CLI for NAS-managed account changes and automatically reconcile related reserved groups and Syncthing state.

## Create or update an account

Send a new password over standard input so it never appears in the process list:

```bash
printf '%s\n' 'new password' | \
  nas-setup account apply \
    --username alice \
    --name 'Alice Example' \
    --email alice@nas.local \
    --group nas_users \
    --password-stdin
```

When an account already exists, omitted name, email, enabled state, groups, and attributes are preserved. Supplying one or more `--group` options replaces the account's complete **reserved NAS identity-role** group set; unrelated custom Authentik groups are preserved. The CLI rejects application capability groups (and the retired `nas_allow_*` groups). Grant application access separately in Authentik after creating the account.

Use `--enabled` or `--disabled` only when you intend to change the account state.

## Grant administrator access

Administrator membership is intentionally explicit:

```bash
nas-setup account apply \
  --username operator \
  --email operator@nas.local \
  --administrator \
  --enabled \
  --set-password
```

`nas_admin` must always retain at least one enabled explicit member. Plans that would remove the final administrator are rejected before the first write. Replacing the sole administrator in one plan is supported: the new administrator is added before the old one is demoted.

## Disable an account

```bash
nas-setup account disable alice
```

Disabling an account:

- removes reserved NAS administrator and identity-role groups;
- marks the Authentik account inactive;
- adds `nas_disabled`;
- reconciles managed Syncthing state;
- preserves unrelated custom Authentik groups; and
- preserves the user's ZFS data.

## Application capabilities

`nas_users` is a baseline identity group, not an application-access grant. Managed Services V2 compiles one Authentik capability group per declared service capability, and the default V2 seed declares these ordinary-user access groups:

- `application.copyparty.files`
- `application.copyparty.webdav`
- `application.syncthing.access`
- `application.vaultwarden.access`

That list is not the complete seed: each application the seed includes also declares an administrator capability group (`application.copyparty.admin`, `application.syncthing.admin`, `application.vaultwarden.admin`, `application.cockpit.admin`), and any service added to `services.yaml` adds its own names. [Account and permission model](../permissions.md) lists both sets and the routes they satisfy.

Assign those groups in Authentik, not through `nas-setup account apply`. The retired `nas_allow_*` and `nas_deny_*` groups are not V2 authorization rules.

## Password handling

Prefer Authentik's UI for normal password changes and MFA recovery. When using NAS CLI commands, use `--password-stdin` or the interactive `--set-password` path rather than putting a password in a command argument or persistent configuration file.
