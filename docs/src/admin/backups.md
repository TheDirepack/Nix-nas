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

## Manual checks

```console
sudo systemctl start nas-syncoid.service
sudo systemctl start restic-backups-nas-boot-system.service
```

Also verify the scheduled restore-check service. A backup is not considered proven merely because the backup command exited successfully; the restore verifier must be able to reconstruct the protected state in isolated scratch storage.

For disaster-recovery order and independent-storage requirements, use the [Recovery runbook](../reference/project-RECOVERY.md).
