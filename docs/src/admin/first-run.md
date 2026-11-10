# First start

`nas-first-start.service` runs automatically at each installed boot when
`nas.firstStart.enable` is true. It inspects the configured setup file and
publishes a password-free state document. It prepares the resumable workflow;
it does not expose Cockpit while KeePassXC secrets, ZFS, and protected services
are locked.

The service does not silently create a pool, read a KeePassXC password, or make
identity changes. It prepares the resumable workflow and shows one of these
states in `nas-setup status`:

- `configuration-missing`: create the storage plan in the wizard or supply a reviewed JSON file;
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
nas.firstStart.configFile = "/var/lib/nas-first-start/first-run.json";
```

To retain a plan previously stored at `/etc/nixos/nixos-nas/first-run.json`,
set `nas.firstStart.configFile` to that path explicitly before upgrading.
Existing plans are never imported or overwritten automatically.

Installation readiness permits the default plan to be absent before setup starts,
so the wizard can create it. An explicit custom path must already contain a
root-owned plan. After setup starts, the original plan remains required for recovery.

`nas-setup` performs the actual appliance workflow by calling the existing
component authorities in their required order. It does not replace NixOS,
KeePassXC, Authentik, CopyParty, or ZFS.

## First-boot Authentik access

The first-boot Authentik setup identity is `akadmin`. Its **Authentik password is
randomly generated on first boot**, independently of the Linux bootstrap login.
It is kept in a private, root-owned boot-side environment file rather than in the
Nix store, release notes, or the installer image. From a trusted local console or
a previously authorized SSH recovery session, retrieve only the password:

```bash
sudo sed -n 's/^AUTHENTIK_BOOTSTRAP_PASSWORD=//p' /var/lib/nas-control-plane/authentik/environment
```

Do not share the full environment file: it also contains the signing secret and
bootstrap API token. Record the password securely until first start completes,
then retire the bootstrap identity. An incomplete upgrade with an older
password-less boot environment must be recovered locally; it will not start
Authentik's initial-setup flow anonymously.

The separate **Linux bootstrap login** also uses username `akadmin`. Development
builds use `nas-admin-first-boot`; tagged releases publish the temporary Linux
password in their release notes. The Linux login requires a password change at
first local console login. Do not use that Linux password to sign in to Authentik.

The setup workflow creates the administrator you choose, verifies that account
as the first permanent Linux recovery administrator and as an enabled
Authentik `nas_admin` member. Its Linux home is
`<nas.zfsRoot>/homes/<username>`, never `/home/<username>`. Setup then removes
the disposable local bootstrap account and retires the bootstrap Authentik
identity. Do not use either bootstrap identity for normal administration.

The initial Linux and Authentik logins have separate bootstrap passwords. The
wizard asks separately for the KeePassXC database password because it only
unlocks the appliance secret database; it is not an account credential.
KeePassXC, Authentik, and PostgreSQL remain under
`/var/lib/nas-control-plane` on the system partition so they are available at
the unlock boundary. Setup discards any pre-existing `NAS.kdbx` and creates a
fresh KeePassXC database with the password entered in the wizard. It also
discards the temporary Authentik/PostgreSQL state and regenerates clean
databases there; it never moves them onto ZFS. Recover any needed entries from
an old database before beginning first setup because setup does not retain it.
The Storage step includes an explicit ZFS encryption toggle, enabled by
default. When enabled, setup creates the KeePassXC database first and uses its
new dataset key to create the encrypted ZFS partition. Turning the toggle off
is an explicit choice for that installation and is recorded in setup state.

The browser wizard keeps this boundary out of the setup form: Authentik is the
temporary access gate, not a separate configuration step. The wizard focuses
on the administrator account, storage plan, and final confirmation. Host locale
remains declarative NixOS configuration rather than a second mutable setup
authority.

On a fresh appliance, select data disks and a pool layout in the wizard and
choose **Review storage plan**. The CLI validates device use and creates the
missing root-owned plan without formatting disks. It refuses to replace an
existing plan or one whose setup has started. The destructive confirmation
remains a separate step.

For advanced preconfigured installations, copy `setup/first-run.example.json`
and edit it outside the Nix store. The file
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
nas-setup validate-config /var/lib/nas-first-start/first-run.json
```

## Complete first start

On the first installed boot, complete setup through the browser wizard: sign
in at the appliance address with the bootstrap Authentik identity above and
open the First start wizard. The wizard shows the exact pool, dataset,
topology, stable device paths, and SHA-256 plan digest prepared from the
configuration file; it collects the KeePassXC database password and the
administrator account, submits the guarded first-start job, and reports
progress until the appliance is complete.

Only one first-start submission can own the wizard's active-job tracking at a
time. A second submission returns HTTP 409 while the matching systemd worker
or detached storage-host work is still active, without replacing the tracked
job or its capability. Submission, resume and reboot requests also return
HTTP 409 while another tracking transition is in progress.

Refresh and resume through the reauthorized wizard after an interruption.
If systemd confirms the worker stopped and no detached storage-host work
remains, resume reports the interrupted job as failed instead of polling a
stale `pending` or `running` record forever. The original durable progress
and diagnostics are retained. Review the setup journal before choosing
**Retry setup** and confirming possible password reapplication; this does not
acknowledge or bypass a `manual-recovery-required` journal. An unavailable or
ambiguous systemd query returns HTTP 503 and preserves the existing job and
capability; repair the query failure rather than deleting tracking files.

The setup API gives clients 30 seconds to send the complete request headers and
body. After a valid request arrives, status preparation and job submission use
their existing command timeouts; the request-read deadline does not discard a
legitimate processing response. A disconnected browser still does not cancel
the detached worker. Refresh and resume to recover its progress.

The browser wizard is the primary first-start interface. Cockpit links to this
same wizard instead of maintaining a second setup form. CLI commands own plan,
identity and storage validation, authorization, locking, journal and execution.
For trusted backend/recovery integrations, `nas-setup first-run` also accepts
`--secret-payload-stdin`: one bounded JSON line containing `keepass` and the
administrator's `username`, `name`, `email`, and `password`. The same secret
validator runs in the API and detached worker. This input does not bypass the
configured local recovery administrator, plan digest or exact disk confirmations.
Keep secrets out of arguments, environment variables and persistent JSON files.

When the plan creates a pool, the wizard requires the destructive-storage
confirmation and the displayed SHA-256 plan digest before it will submit. The
backend re-reads and normalizes the root-owned configuration, recomputes the
digest, copies the exact device list into the guarded invocation, and rejects
a stale digest or mismatched device confirmation.

Setup is resumable. Completed stages are reused only after their live
postcondition probes still pass. A `manual-recovery-required` journal never
automatically resumes; repair the reported authority and run
`nas-setup reconcile-first-run --note 'what was repaired'`, or use Cockpit's
First start page, before retrying. The wizard shows this state, and the step
that stopped, before you enter passwords, and it does not offer a retry until a
refreshed plan shows the acknowledgement. An interrupted journal that can resume
is also shown; resume it with the same administrator and KeePassXC passwords.
Keep the recovery terminal available until the protected stack is ready.

Identity database regeneration pauses the timers that trigger identity and
Syncthing synchronization and drains their pending jobs before stopping
Authentik/PostgreSQL. Previously active timers resume only after regeneration
succeeds. If this stage fails, leave those timers stopped while repairing the
identity stack; their names are logged in the first-start worker's journal.
After recovery and successful setup, use `sudo systemctl start EXACT.timer`
for each previously active timer still paused. Do not start synchronization
against partially regenerated databases.

The workflow prompts once for the KeePass database password. It then:

1. creates the setup KeePass database or verifies the database from a resumable setup stage;
2. runs `nas-secrets init` idempotently;
3. verifies existing ZFS storage or creates the explicitly confirmed pool and
   managed dataset;
4. creates the permanent local recovery administrator with a private home on
   that ZFS dataset and removes the disposable local bootstrap account;
5. activates secrets and starts the protected service target;
6. bootstraps reserved Authentik groups;
7. creates or updates configured accounts and passwords, including the chosen
   administrator;
8. creates only the ZFS-backed personal directories required by file-enabled
   accounts, leaving CopyParty ACLs and volumes authoritative;
9. reconciles managed Syncthing objects when enabled;
10. applies requested feature lifecycle modes;
11. runs mount, identity, and optional repository preflight checks; and
12. writes a password-free completion report to
    `/var/lib/nas-setup/state.json`.

## First-start commands and automation

Review the prepared plan from the recovery plane as the configured local
administrator, not as root:

```bash
nas-setup prepare-first-start --config /var/lib/nas-first-start/first-run.json
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

Before setup completes, the Authentik gate protects every management route.
The setup wizard is reachable only after signing in with the bootstrap
Authentik identity. After setup, a locked boot serves only a static notice that
explains how to run `sudo nas-secrets activate` from the recovery plane; see
[Locked-state unlock](../locked-unlock.md).

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

Successful setup provisions and verifies a scoped runtime Authentik token and
retires the bootstrap authority. Routine post-setup token replacement is not
required. If an incomplete or older setup leaves a runtime-token warning, use
the [Authentik service-token recovery guidance](authentik.md#service-token).
