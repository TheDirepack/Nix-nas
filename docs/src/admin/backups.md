# Snapshots, replication, and backups

The appliance uses separate tools for separate recovery jobs. Do not treat a same-pool snapshot or backup as protection from loss of that pool.

## ZFS snapshots and replication

Sanoid owns snapshot retention. Optional Syncoid replication copies `nas.zfsDataset` and child datasets to another ZFS target.

```nix
nas.zfsReplication = {
  enable = true;
  target = "backup@backup-nas:tank/replicas/nas";
};
```

When replication is enabled, **NAS Overview** exposes **Replicate ZFS now** in the storage card.

## Boot and appliance-state backup

The Restic job `nas-boot-system` protects boot/system recovery material and selected mutable service state, including machine identity, Nix configuration, KeePass, Authentik, CopyParty databases/configuration, Syncthing identity, and NAS control state.

If no external repository is configured, the default repository is `<nas.zfsRoot>/backups/restic-system`. That is useful for boot-device rollback and can itself be replicated with ZFS, but by itself it does **not** protect against losing the same pool.

CopyParty SQLite databases are staged with online backups instead of copying the entire live state tree, which also contains the mounted NAS data hierarchy.

### Off-pool repository

Restic reads the repository from `nas.backup.repositoryFile`, a root-owned `0600` file holding one repository string. Installation readiness rejects the file, and a `nas.backup.rcloneConfigFile`, unless root owns them and they grant no group or other access. It also rejects a repository on the managed pool, a memory-backed filesystem, or a filesystem it cannot identify, and a backend with no destination. Any Restic backend works, including `sftp:`, `rest:`, `s3:`, `b2:` and `rclone:<remote>:<path>`. Keep the file out of Git and the Nix store, because a repository string can contain credentials.

```nix
nas.backup = {
  enable = true;
  passwordFile = "/run/secrets/restic-password";
  repositoryFile = "/run/secrets/restic-repository"; # contains e.g. rclone:gdrive:nas-backup
  rcloneConfigFile = "/run/secrets/rclone.conf";     # only for rclone: repositories
};
```

The job always backs up its complete profile. There is no partial or "config-only" mode.

**Migrating from `nas.backup.remote.*`.** These options are retired, and evaluation stops until you remove them:

- `remote.enable`, `remote.provider` and `remote.rcloneRemote`: write the repository to the file above. The old default was `rclone:<rcloneRemote>`, or `rclone:<provider>:nas-backup` when `rcloneRemote` was empty.
- `remote.scope`: delete it. It never limited what was backed up.
- `remote.rcloneConfigFile`: still accepted, with a warning, as `nas.backup.rcloneConfigFile`. It is valid only with `repositoryFile`.

A top-level `backup.remote` block in `services.yaml` was never applied. A block that only holds the old defaults is dropped. Any other value fails validation, so Cockpit mode changes and desired-state saves fail until it is gone. The Cockpit form cannot remove it, because the schema no longer has a `backup` property. Configure the repository in Nix, then delete the whole top-level `backup:` block from `/var/lib/nas-control/services.yaml`, either in the raw YAML editor or on the console.

### Status in Cockpit

The **Backup** card on the Cockpit overview shows what `nas-backup-status status` reports, as separate observations:

- **Restic repository**: where the configured repository is. *Off-pool* means a network backend or a local path outside the managed pool. *Same pool* is rollback storage only. *System disk* means the path is on the root filesystem; check that its intended disk is mounted. *Volatile* means a memory-backed filesystem such as `/run`. The repository string itself is never displayed.
- **Last backup**: the result systemd recorded for the last `nas-boot-system` run against the current repository. A result recorded for a previous repository is not shown. *Not recorded* means a run started and has no result yet: it is still running, or its result could not be written.
- **Restore verification**: the last isolated restore and validation, on this host, of the snapshot that was latest when verification started. The card says when later backups are not yet verified.
- **Independent restore**: always *Not proven*. Only the boot-device replacement drill in the [Recovery runbook](../reference/project-RECOVERY.md) proves it.

Start a backup or restore verification from **Operations**.

## Durable OCI application state

Keep the V2 service ID stable when replacing an image. Store the application's
logical identity, database, tasks and workspaces in an explicit authoritative
storage attachment, not its container writable layer. Separate rebuildable
cache from that state and put temporary sockets, display locks and scratch
files on tmpfs. For example, adapt this desired-state pattern to an approved
image and configure that application's native state/cache paths:

```yaml
schemaVersion: 3
storageResources:
  app-state:
    path: /tank/apps/example/state
    dataset: tank/nas/apps/example/state
    stateClass: authoritative
    backup: {enabled: true, consistency: zfs-snapshot}
  app-cache:
    path: /tank/apps/example/cache
    stateClass: cache
    backup: {enabled: false}
credentials:
  app-token: {path: /run/nas-secrets/example/token, required: true}
services:
  example:
    name: Example persistent application
    workload: {kind: daemon}
    runtime: {type: oci, image: registry.example.test/team/app:reviewed}
    network: {mode: isolated, outboundDefault: deny}
    storage:
      - {resource: app-state, mountPath: /state, access: write}
      - {resource: app-cache, mountPath: /cache, access: write}
    credentials:
      - {credential: app-token, use: file, mountPath: /run/secrets/token}
    sandbox:
      mode: strict
      tmpfs: [{path: /tmp, sizeBytes: 67108864}]
```

This is a configuration pattern, not a runnable image recommendation. Provision
the datasets/directories and set ownership for the **actual** runtime UID/GID
before activation. Declaring a resource does not create its dataset or prove
rootless/user-namespace isolation. Keep credential values in KeePass-managed
runtime secrets; the YAML records references only. Backup metadata selects the
existing backup machinery; it does not make an arbitrary live database safe.

For a recovery drill:

1. Unlock the NAS manually and confirm the exact dataset, mounts, service ID,
   image version and credential references. Preserve the current desired-state
   document using the normal configuration backup.
2. Use the application's native online backup for a live SQLite/WAL database,
   or stop **every** writer before taking a ZFS snapshot of its dedicated data
   dataset. Do not copy a live `.db` file alone or omit its WAL. A filesystem
   consistency check is not proof of logical application consistency.
3. Preserve the current data and a safety snapshot. Prefer restoring/cloning
   the selected recovery point to a separate dataset first. With writers still
   stopped, verify ownership/modes and use the existing revision-checked V2
   editor to point the **same** resource/service at the restored data. Keep the
   credential attachment intact; do not restore obsolete tokens over a revoked
   credential.
4. Start the app with a schema-compatible image and run its integrity and
   application-level checks. Compare identity, task/workspace records and the
   mounted credential source. If migration or startup fails, keep both datasets,
   inspect the unit journal, and return the resource to the retained dataset
   with its compatible image. An image rollback does not undo a database migration.
5. Remove/archive only the V2 definition when retaining data. Inspect retained
   datasets and independent backups separately; do not repurpose another
   application's data or destroy it as part of definition cleanup.

`nas-state` migrates control configuration, not these application databases.
Use Restic, ZFS replication or application-native recovery for bulk state; a
same-pool snapshot is not independent disaster recovery. GUI display sockets,
viewer streams, input state and temporary session tokens are recreated, not
restored as durable application identity. Creator-scoped delegated lifecycle
and cross-creator data restrictions are not implemented by this pattern.

## Migrating pre-tag Restic snapshots

The managed `nas-boot-system` profile selects its Restic parent by `host,tags` and applies retention only to snapshots carrying the `nas-boot-system` tag. Snapshots written before that tag existed are untagged, so `forget` skips them and `prune` cannot reclaim their data. Account for them before deploying the tag-filtered profile; a fresh installation has nothing to migrate.

Run these commands with the configured `nas.backup.passwordFile` and repository: `--repository-file` when `nas.backup.repositoryFile` is set, otherwise `--repo` with `nas.backup.localRepository`, which defaults to `<nas.zfsRoot>/backups/restic-system`. The examples use the local repository and the current `keep-*` policy.

List the untagged snapshots belonging to this job. Every `nas-boot-system` snapshot includes `/boot`, so the path filter scopes these commands to this profile:

```console
sudo RESTIC_PASSWORD_FILE=/path/to/restic-password \
  restic --repo /tank/backups/restic-system snapshots --path /boot --json \
  | jq -r '.[] | select((.tags // []) | index("nas-boot-system") | not) | "\(.short_id // .id) \(.hostname) \(.time)"'
```

Validate the future retention selection with the profile's grouping, tag, and `keep-*` values:

```console
sudo RESTIC_PASSWORD_FILE=/path/to/restic-password \
  restic --repo /tank/backups/restic-system forget --dry-run \
    --group-by host,tags --tag nas-boot-system \
    --keep-daily 14 --keep-weekly 8 --keep-monthly 12 --keep-yearly 3
```

The dry run must list only `nas-boot-system` snapshots. Untagged snapshots stay outside that selection until they are retagged.

Adopt them into the profile group:

```console
sudo RESTIC_PASSWORD_FILE=/path/to/restic-password \
  restic --repo /tank/backups/restic-system tag \
    --path /boot --tag '' --add nas-boot-system
```

`restic tag` rewrites snapshot metadata only; it moves no data and needs no prune. Confirm no untagged snapshots remain, then rerun the dry run above to see the migrated snapshots inside the retention selection:

```console
sudo RESTIC_PASSWORD_FILE=/path/to/restic-password \
  restic --repo /tank/backups/restic-system snapshots --path /boot --json \
  | jq '[.[] | select((.tags // []) | index("nas-boot-system") | not)] | length'
```

The count must be `0`. If the repository is shared with other Restic jobs that also back up `/boot`, do not use the path filter above; pass the exact snapshot IDs from the first listing to `restic tag` and verify each one.

To discard the legacy snapshots instead of adopting them, pass their IDs to `restic forget`; the next successful profile run prunes the unreferenced data because the profile sets `prune = true`. Pruning takes the repository lock and cannot be undone, so keep it outside the backup window.

## Manual checks

```console
sudo systemctl start nas-syncoid.service
sudo systemctl start restic-backups-nas-boot-system.service
```

Also verify the scheduled restore-check service. A backup is not considered proven merely because the backup command exited successfully; the restore verifier must be able to reconstruct the protected state in isolated scratch storage. `sudo nas-backup-status status` prints the same observations as the Cockpit card.

For disaster-recovery order and independent-storage requirements, use the [Recovery runbook](../reference/project-RECOVERY.md).

## Interrupted control-configuration restore

A failed automatic rollback or an interrupted `nas-state restore` blocks further
restores. Inspect `/var/lib/nas-state/restore-operation.json` from a local
administrator console or recovery SSH session (use `NAS_STATE_RESTORE_JOURNAL` if overridden). Preserve the journal, its `rollbackBundle`, the signing
key and any relevant update recovery marker. `nas-state prune-rollbacks` pins the
rollback named by an unresolved journal regardless of retention count or age.
An unreadable or unrecognized journal stops restore and pruning for inspection.

Review `status`, `unitSnapshot`, `primaryError` and `rollbackError`. An interrupted
`preparing` phase may have changed nothing; `capturing-rollback` may name an
incomplete bundle. Validate the rollback with `nas-state validate` before using
it. Later phases may have stopped services or partially applied state. Repair
configuration and restore the recorded service state using the recovery plane,
then verify application health. Acknowledgement itself performs no repair.

After completing manual recovery, archive the evidence and release the restore
block with the exact `restoreId` from the journal and the current hostname:

```bash
sudo nas-state acknowledge-recovery --restore-id <restoreId> --confirm-host <hostname>
```

This saves the original journal under `restore-recovery/<restoreId>.json` beside
the active journal before marking recovery acknowledged. Subsequent restores
start a fresh record. Acknowledgement releases the retention pin, so copy any
rollback you still need to a private directory outside the automatic rollback
root **before** acknowledging. To recover by replaying that copy, validate it,
review its diff, ensure out-of-band access and safe service state, acknowledge
the reviewed interruption, then use the ordinary guarded `nas-state restore`
command against the copy with the required hostname, sensitive, absence and
network acknowledgements. Verify application health afterward. Do not delete
the journal to bypass recovery, or acknowledge a failed update without also
following its update recovery procedure.
