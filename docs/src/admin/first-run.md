# First start

`nas-first-start.service` runs automatically at each installed boot when
`nas.firstStart.enable` is true. It inspects the configured setup file and
publishes a password-free state document. It prepares the resumable workflow;
it does not expose Cockpit while KeePassXC secrets, ZFS, and protected services
are locked.

The service does not silently create a pool, read a KeePassXC password, or make
identity changes. It prepares the resumable workflow and shows one of these
states in `nas-setup status`:

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

## First-boot Authentik access

The first-boot Authentik setup identity is always `akadmin`. The password depends
on the artifact you are running:

- a development checkout or development-built image uses the fixed
  `nas-admin-first-boot` password so first-run, VM, and browser tests remain
  repeatable;
- an automated tagged GitHub Release uses the five-word Diceware password shown
  in that release's notes. The same password is embedded in that release-only
  source commit and package.

Do not copy a release password into `main`, and do not assume
`nas-admin-first-boot` works for a tagged release. If you are installing a
published release, use the credentials from the matching GitHub Release notes.

The setup workflow creates the administrator you choose, verifies that account
is an enabled `nas_admin` member, and then retires the bootstrap Authentik
identity. Do not use the bootstrap identity for normal administration.

The browser wizard keeps this boundary out of the setup form: Authentik is the
temporary access gate, not a separate configuration step. The wizard focuses
on the administrator account, storage plan, and final confirmation. Host locale
remains declarative NixOS configuration rather than a second mutable setup
authority.

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

## Complete first start

On the first installed boot, complete setup through the browser wizard: sign
in at the appliance address with the bootstrap Authentik identity above and
open the First start wizard. The wizard shows the exact pool, dataset,
topology, stable device paths, and SHA-256 plan digest prepared from the
configuration file; it collects the KeePassXC database password and the
administrator account, submits the guarded first-start job, and reports
progress until the appliance is complete.

The browser path is the only first-start execution surface. `nas-setup` on the
recovery plane stays read-only for this workflow: use
`nas-setup prepare-first-start` to review the published `ready` state and plan
digest, and `nas-setup status` to watch completion, but do not expect the
interactive `first-run` subcommand to perform setup; the wizard's submission
path is what validates the plan digest, confirms every storage device, and
runs the guarded job.

When the plan creates a pool, the wizard requires the destructive-storage
confirmation and the displayed SHA-256 plan digest before it will submit. The
backend re-reads and normalizes the root-owned configuration, recomputes the
digest, copies the exact device list into the guarded invocation, and rejects
a stale digest or mismatched device confirmation.

Setup is resumable. Completed stages are reused only after their live
postcondition probes still pass. A `manual-recovery-required` journal never
automatically resumes; repair the reported authority and run
`nas-setup reconcile-first-run --note 'what was repaired'` before retrying.
Keep the recovery terminal available until the protected stack is ready.

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

## First-start commands and automation

Review the prepared plan from the recovery plane as the configured local
administrator, not as root:

```bash
nas-setup prepare-first-start --config /etc/nixos/nixos-nas/first-run.json
nas-setup status
```

Submit the workflow through the browser wizard. The submission path validates
`sudo` authorization, re-reads the root-owned configuration, confirms the plan
digest and every storage device, and runs the guarded first-start job as an
authorized root operation without exposing the KeePass or administrator
passwords to a shell. Any account `passwordFile` referenced by the JSON must
exist when the job runs; remove that field after bootstrap when a rerun should
preserve the current Authentik password.

## Browser bootstrap and locked boot

Before setup completes, Caddy serves the static `/setup` guidance page and the
Authentik gate protects every management route. The setup wizard itself is
reachable only after signing in with the bootstrap Authentik identity.

During first start, Authentik creates its temporary `akadmin` bootstrap identity
using the credential for the exact source artifact: `nas-admin-first-boot` for
the development tree, or the five-word password published with an automated
tagged release. Setup creates and verifies the chosen `nas_admin` administrator,
then retires that bootstrap identity. After protected services are ready, use
Authentik through Caddy for all browser access.

The Storage step links to Cockpit Storage for disk partitioning or pool import,
and to the Cockpit terminal for advanced ZFS work. Return to the wizard and
refresh the plan after changing the disk layout; the destructive operation
still uses the reviewed device list and plan digest.

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

Every configured device must be confirmed individually, and all new-pool
creation requires the destructive opt-in in the wizard. Before writing, the
setup backend verifies that each path resolves to a block device and rejects
traversal paths or multiple aliases for the same underlying disk.

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
