# First start

`nas-first-start.service` runs automatically at each installed boot when
`nas.firstStart.enable` is true. It inspects the configured setup file and
publishes a password-free state document for Cockpit before the Cockpit socket
is opened. Cockpit therefore remains reachable while KeePassXC secrets, ZFS,
and the protected application stack are locked.

The service does not silently create a pool, read a KeePassXC password, or make
identity changes. It prepares the resumable workflow and shows one of these
states in Cockpit:

- `configuration-missing`: create the configured JSON file;
- `configuration-invalid`: correct the reported schema or policy error;
- `state-invalid`: repair or recover the setup journal/state file;
- `ready`: review the exact non-secret storage, account, feature plan, and plan
  digest, then enter the KeePassXC database password;
- `configuration-changed`: the normalized plan differs from the plan that was
  completed and must be reviewed again;
- `state-drift`: setup state exists but one or more live authority probes no
  longer satisfy it;
- `complete-unverified`: setup finished but final host preflight was explicitly
  skipped through the CLI; or
- `complete`: the completed plan and authority probes are verified.

The defaults are:

```nix
nas.firstStart.enable = true;
nas.firstStart.configFile = "/etc/nixos/nixos-nas/first-run.json";
```

`nas-setup` performs the actual appliance workflow by calling the existing
component authorities in their required order. It does not replace NixOS,
KeePassXC, Authentik, CopyParty, ZFS, or the feature controller.

## Prepare the configuration

Copy `setup/first-run.example.json` and edit it outside the Nix store. The file
may define storage creation, Authentik accounts, reserved NAS groups, and initial
feature modes.

Do not place plaintext passwords in the JSON file. Each account can reference a
private password file:

```bash
install -m 0600 /dev/null /run/keys/nas-alice-password
read -r -s -p 'Alice password: ' password
printf '%s\n' "$password" > /run/keys/nas-alice-password
unset password
```

`nas-setup` rejects password files with group or other permissions, rejects
symlinks, requires a regular UTF-8 file containing exactly one non-empty line,
and opens each file exactly once. Passwords are retained only in a transient
in-memory Authentik plan, sent over stdin to `nas-identity-sync`, removed from
the plan on every exit path, and omitted from
`/var/lib/nas-setup/state.json`.

The schema is strict: unknown top-level, storage, or account fields are
rejected so a misspelled safety or account field cannot silently fall back to a
default. Password-file paths must be absolute.

Validate the file before making changes:

```bash
nas-setup validate-config /etc/nixos/nixos-nas/first-run.json
```

## Complete the automatic Cockpit workflow

Open Cockpit after the first installed boot. The NAS page displays the setup
state published by `nas-first-start.service`. When the state is `ready`, review
the exact pool, dataset, topology, and stable device paths, enter the KeePassXC
database password, and start setup.

When the plan creates a new pool, Cockpit requires a separate destructive-storage
checkbox. Cockpit also sends the displayed SHA-256 plan digest. The backend
re-reads and normalizes the root-owned configuration, recomputes the digest,
copies the exact configured device list into the guarded CLI invocation, and
refuses a stale digest or mismatched device confirmation. It sends the KeePassXC
password only over the spawned process's stdin; the password is not placed in an
argument, environment variable, state file, or first-start status document.

Setup is resumable. Completed stages are reused only after their live
postcondition probes still pass. A `manual-recovery-required` journal never
automatically resumes; repair the reported authority and run
`nas-setup reconcile-first-run --note 'what was repaired'` before retrying. If
resume reaches the account-password stage, Cockpit requires a separate checkbox
before password changes can be repeated. Cockpit stays available while
protected services remain locked.

The workflow prompts once for the KeePass database password. It then:

1. verifies the configured KDBX database or creates it when missing;
2. runs `nas-secrets init` idempotently;
3. verifies existing ZFS storage or creates the explicitly confirmed pool and
   managed dataset;
4. activates secrets and starts the protected service target;
5. bootstraps reserved Authentik groups;
6. creates or updates configured accounts and passwords;
7. creates only the ZFS-backed personal directories required by file-enabled
   accounts, leaving CopyParty ACLs and volumes authoritative;
8. reconciles managed Syncthing objects when enabled;
9. applies requested feature lifecycle modes;
10. runs mount, identity, and optional repository preflight checks; and
11. writes a password-free completion report to
    `/var/lib/nas-setup/state.json`.

## CLI fallback and automation

The same workflow can be run from a shell as the configured local
administrator, not as root:

```bash
status_json="$(nas-setup prepare-first-start --config /etc/nixos/nixos-nas/first-run.json)"
plan_digest="$(printf '%s' "$status_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["planDigest"])')"
nas-setup first-run \
  --config /etc/nixos/nixos-nas/first-run.json \
  --confirm-plan-digest "$plan_digest"
```

The CLI validates `sudo` authorization before it asks for or reads the KeePass
password, refreshes the cached authorization during long setup runs, and makes
every subsequent privileged call noninteractive. This preserves administrator
ownership of the KDBX file while preventing sudo from consuming account-plan or
secret data sent to a child command over stdin.

For automation, authorize sudo first and then send one KeePass password line
over stdin:

```bash
sudo -v
cat /run/keys/nas-keepass-password | \
  nas-setup first-run \
    --config /etc/nixos/nixos-nas/first-run.json \
    --confirm-plan-digest "$plan_digest" \
    --keepass-password-stdin
```

The KeePass password file in this example is an operator-created transient
input. It is not created or retained by the NAS project. Any account
`passwordFile` referenced by the JSON must also exist on every run; remove that
field after bootstrap when a rerun should preserve the current Authentik
password.

## New-pool safeguards

Pool creation supports `single`, `stripe`, `mirror`, `raidz1`, `raidz2`, and
`raidz3`. Use stable `/dev/disk/by-id/...` paths. The CLI sets `ashift=12` by
default, enables `compression=zstd`, disables `atime`, uses `xattr=sa` and
`acltype=posixacl`, leaves the pool root unmounted, and enables pool autotrim.
The `ashift` value can be changed in the setup file before creation.

Example mirror configuration:

```json
{
  "storage": {
    "createPool": true,
    "devices": [
      "/dev/disk/by-id/ata-EXACT_DISK_0",
      "/dev/disk/by-id/ata-EXACT_DISK_1"
    ],
    "topology": "mirror",
    "wipeDevices": true,
    "ashift": 12
  }
}
```

Every configured device must be repeated on the command line, and all new-pool
creation requires the destructive opt-in. Before writing, the CLI verifies that
each path resolves to a block device and rejects traversal paths or multiple
aliases for the same underlying disk:

```bash
nas-setup first-run \
  --config /etc/nixos/nixos-nas/first-run.json \
  --confirm-storage-device /dev/disk/by-id/ata-EXACT_DISK_0 \
  --confirm-storage-device /dev/disk/by-id/ata-EXACT_DISK_1 \
  --confirm-plan-digest "$plan_digest" \
  --allow-destructive-storage
```

`wipeDevices` controls whether `wipefs` runs first; the destructive flag is
required even when wiping is disabled because creating a pool writes ZFS labels.
Existing pools and datasets are never destroyed or recreated by an idempotent
rerun. The legacy singular `device`/`wipeDevice` fields remain accepted for old
single-disk test configurations, but new files should use `devices` and
`wipeDevices`.

The short `/dev/vdb` form is used only by the disposable QEMU tests.

## Account management after setup

After first-start, manage individual accounts with the runtime account commands described in [Accounts and access](accounts.md). Authentik remains authoritative; the NAS command is a guarded convenience for reserved NAS groups, password changes, and Syncthing reconciliation.

## Idempotency and authority

Rerunning the same first-run file updates only the declared reserved NAS group
memberships while preserving unrelated Authentik groups. Accounts carry the
`nasManagedBySetup` attribute so the optional
`deactivateMissingManagedAccounts` mode can disable accounts removed from the
file without touching manually managed Authentik accounts.

The initial runtime Authentik API token remains the bootstrap token until the
administrator creates a narrower service-account token and stores it with
`nas-secrets set-authentik-token`. Complete that post-bootstrap hardening step
before production use.
