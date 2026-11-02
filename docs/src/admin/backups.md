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

Also verify the scheduled restore-check service. A backup is not considered proven merely because the backup command exited successfully; the restore verifier must be able to reconstruct the protected state in isolated scratch storage.

For disaster-recovery order and independent-storage requirements, use the [Recovery runbook](../reference/project-RECOVERY.md).
