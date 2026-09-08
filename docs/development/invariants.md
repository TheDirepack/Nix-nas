# Non-negotiable invariants

## Sources of truth

- NixOS owns packages, units, listeners, sandboxes, defaults, and evaluation-time validation.
- Authentik owns human identities, passwords, MFA, groups, application access, and user-editable Syncthing device attributes.
- KeePassXC owns machine secrets. Its database password is operator input and is never persisted by the project.
- CopyParty owns volumes, paths, ACLs, flags, quotas, share links, WebDAV, and file policy.
- Syncthing owns its runtime configuration; the reconciler modifies only reserved `nas-*` objects.
- V2 `services.yaml` owns application lifecycle mode and on-demand idle timestamps (seed-once, then YAML/Cockpit is authority; Nix never regenerates it).

Do not introduce another account database, share database, secret database, or mutable desired-state database. `JSON Schema` at `/etc/nas-control/managed-services-v3.schema.json` is the sole structural/UI contract.

## Mutable appliance state

Runtime-managed upstream state is authoritative in appliance-managed mode. `nas-state` is the versioned export, diff, validation, and guarded restore boundary. Sensitive authorities require explicit inclusion; restore creates and validates a rollback bundle before applying changes. Nix remains authoritative for packages, units, listeners, and immutable defaults.

## Locked boot

Local console, SSH, or hardware KVM and a local PAM administrator are the recovery plane. Authentik, CopyParty, and protected services remain stopped until secret activation and storage validation succeed. Caddy may serve static setup guidance, but no browser management endpoint is exposed while locked. An Authentik administrator is not automatically a Linux/PAM administrator.

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

- KeePassXC, Authentik, and PostgreSQL are unlock/control-plane authorities and remain on the system partition under `/var/lib/nas-control-plane`; they must never be promoted into the managed ZFS data root.
- Permanent human home directories and user/application data belong on the managed ZFS partition. Temporary first-start Linux home data is retired with the bootstrap identity.
- New pool creation requires explicit destructive opt-in and exact confirmation of every unique block device.
- Dataset mount guards must verify the exact dataset and mountpoint before protected services start.
- Snapshot restore creates a safety snapshot first.
- Same-pool Restic is boot/appliance recovery, not independent whole-pool backup.
- Native backup artifacts are confined to the dedicated staging root `/run/nas-control/backup-staging/<resource-id>` (derived from the resource identity). Artifact paths outside the staging root or that escape via symlink (`path.resolve`/`relative_to` check) are rejected. Stale artifacts are removed before each preparation, recorded in durable runtime state, and cleaned up on both normal and partial-prepare failure paths.

## Tests

Changes to authentication, root commands, storage destruction, secret activation, or feature lifecycle require behavioral tests. Nix/systemd/network changes also require the QEMU suite before release.

## Deployment boundaries

- Disko examples remain unimported and destructive only when invoked explicitly.
- Authentik superusers and local PAM recovery administrators remain separate authorities.
- Removing an identity does not delete CopyParty data; retained volumes require explicit administrator review.
