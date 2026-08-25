# Snapshots, replication, and backups

The appliance uses separate native mechanisms for two different recovery domains. Do not treat a same-pool snapshot or backup as protection from loss of that pool.

## Encrypted ZFS data-domain backup

Sanoid owns snapshot retention. Optional Syncoid replication copies the complete `nas.zfsDataset` tree, including Managed Services V2 desired state, generations, application state, VMs, containers, shares, and other ZFS-hosted data, to another ZFS target.

```nix
nas.zfsReplication = {
  enable = true;
  target = "backup@backup-nas:tank/replicas/nas";
};
```

When native ZFS encryption is enabled, the backup policy adds Syncoid `--sendoptions=w`, which makes Syncoid use a raw `zfs send -w`. The replicated ZFS stream therefore preserves native encrypted data instead of building a plaintext archive. Recursive replication remains handled by Syncoid rather than by a second application-specific backup framework.

When replication is enabled, **NAS Overview** exposes **Replicate ZFS now** in the storage card.

A ZFS replication target should normally be on independent storage. Replication to another dataset on the same physical pool is useful for testing or local rollback but is not protection from whole-pool loss.

## Root/control-plane Restic backup

The Restic job `nas-boot-system` is the separate root/control-plane recovery domain. It backs the root filesystem and `/boot` while explicitly excluding runtime pseudo-filesystems, caches, restore scratch space, the live PostgreSQL data directory, and the complete mounted `nas.zfsRoot` tree.

The root backup therefore contains the pieces required to recover the appliance before ZFS is available, including:

- the NixOS/system configuration and host state;
- the root-hosted KeePass database (`NAS.kdbx`);
- Caddy and Authentik root-side state;
- a native PostgreSQL custom-format dump of the Authentik database;
- host network/firewall state and other root-side control-plane state.

The live PostgreSQL database directory is not copied while PostgreSQL is running. The backup prepares `authentik.pgdump` with `pg_dump --format=custom`, and restore verification checks it with `pg_restore --list`.

The Restic backup is tagged `root-control-plane`. It does **not** consume Managed Services V2 per-application backup inventories and does **not** contain `${nas.zfsRoot}/nas-control/services.yaml`; that desired-state authority belongs only to the encrypted ZFS recovery domain.

If no external repository is configured, the default Restic repository is `<nas.zfsRoot>/backups/restic-system`. That is useful for boot-device recovery and, when ZFS replication is enabled, is carried to the replication target with the ZFS dataset. By itself, however, a Restic repository on the same pool is not protection against losing that pool.

## Recovery order

The intended disaster-recovery order is:

1. Restore the root/control-plane Restic backup onto replacement boot storage.
2. Boot the restored control plane and provide the user-known KeePass master password.
3. Recover the ZFS key from `NAS.kdbx`.
4. Import or receive the replicated encrypted ZFS dataset and load its native ZFS key.
5. Mount the ZFS dataset. The authoritative `services.yaml` and all ZFS-hosted application state become available only at this point.
6. Run Managed Services V2 reconciliation to regenerate runtime projections and start application services.

The root backup and ZFS replication are complementary. A complete bare-metal recovery plan needs a usable copy of each domain.

## Manual checks

```console
sudo systemctl start restic-backups-nas-boot-system.service
sudo systemctl start nas-syncoid.service
```

Also verify the scheduled root-backup restore-check service and periodically test receiving/importing the ZFS replica on isolated recovery storage. A backup is not considered proven merely because the backup command exited successfully.

For disaster-recovery order and independent-storage requirements, use the [Recovery runbook](../reference/project-RECOVERY.md).
