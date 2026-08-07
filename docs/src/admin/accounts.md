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
    --group nas_allow_files \
    --group nas_allow_vault \
    --password-stdin
```

When an account already exists, omitted name, email, enabled state, groups, and attributes are preserved. Supplying one or more `--group` options replaces the account's complete **reserved NAS** group set; unrelated custom Authentik groups are preserved.

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

- removes reserved NAS administrator/capability groups;
- marks the Authentik account inactive;
- adds `nas_disabled`;
- reconciles managed Syncthing state;
- preserves unrelated custom Authentik groups; and
- preserves the user's ZFS data.

## Capability groups

`nas_users` is a baseline identity group, not an application-access grant. Give users only the capabilities they need:

- `nas_allow_files`
- `nas_allow_webdav`
- `nas_allow_syncthing`
- `nas_allow_vault`
- `nas_allow_ai`

Matching `nas_deny_*` groups take precedence. See [Account and permission model](../permissions.md) for the enforcement model.

## Password handling

Prefer Authentik's UI for normal password changes and MFA recovery. When using NAS CLI commands, use `--password-stdin` or the interactive `--set-password` path rather than putting a password in a command argument or persistent configuration file.
