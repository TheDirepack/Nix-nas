# Non-negotiable invariants

## Sources of truth

- NixOS owns packages, units, listeners, sandboxes, defaults, and evaluation-time validation.
- Authentik owns human identities, passwords, MFA, groups, application access, and user-editable Syncthing device attributes.
- KeePassXC owns machine secrets. Its database password is operator input and is never persisted by the project.
- CopyParty owns volumes, paths, ACLs, flags, quotas, share links, WebDAV, and file policy.
- Syncthing owns its runtime configuration; the reconciler modifies only reserved `nas-*` objects.
- The feature controller owns only feature lifecycle mode and on-demand runtime timestamps.

Do not introduce another account database, share database, secret database, or feature configuration store.

## Mutable appliance state

Runtime-managed upstream state is authoritative in appliance-managed mode. `nas-state` is the versioned export, diff, validation, and guarded restore boundary. Sensitive authorities require explicit inclusion; restore creates and validates a rollback bundle before applying changes. Nix remains authoritative for packages, units, listeners, and immutable defaults.

## Locked boot

Cockpit and the local PAM administrator are the recovery plane. Authentik, Caddy, CopyParty, and protected services remain stopped until secret activation and storage validation succeed. An Authentik administrator is not automatically a Linux/PAM administrator.

## Authorization

- `nas_admin` is the only Authentik superuser group and must retain at least one enabled explicit member.
- Ordinary users receive no application capability without `nas_allow_*` membership.
- `nas_disabled` and matching deny groups fail closed.
- Caddy strips client-supplied identity headers before trusted forward-auth headers are used.
- Cockpit privileged actions use a fixed allow-list and validated arguments.

## Secrets and privileged input

- Secrets must not appear in Nix store paths, command arguments, URLs, persistent JSON, browser storage, or environment variables.
- Secret stdin is one bounded nonempty line.
- Password files are absolute, private, regular, non-symlink files and are opened once.
- Long setup operations use pre-authorized, noninteractive sudo; payload stdin must never be consumed by sudo.

## Storage

- New pool creation requires explicit destructive opt-in and exact confirmation of every unique block device.
- Dataset mount guards must verify the exact dataset and mountpoint before protected services start.
- Snapshot restore creates a safety snapshot first.
- Same-pool Restic is boot/appliance recovery, not independent whole-pool backup.

## Tests

Changes to authentication, root commands, storage destruction, secret activation, or feature lifecycle require behavioral tests. Nix/systemd/network changes also require the QEMU suite before release.

## Deployment boundaries

- Disko examples remain unimported and destructive only when invoked explicitly.
- Authentik superusers and local Cockpit/PAM administrators remain separate authorities.
- Removing an identity does not delete CopyParty data; retained volumes require explicit administrator review.
