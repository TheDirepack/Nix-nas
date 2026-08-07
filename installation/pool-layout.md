# Production pool layout record

Fill this in before pool creation and update it after every topology change. Use only stable `/dev/disk/by-id/...` paths.

- Pool name: `tank`
- Dataset mounted at `nas.zfsRoot`: `tank/nas` → `/tank`
- Recorded `networking.hostId`:
- Pool GUID:
- Creation date and command:
- `ashift`:
- Vdev topology and member IDs:
- Spares/cache/log/special vdevs:
- Pool feature flags:
- Root properties (`compression`, `atime`, `xattr`, `acltype`, `autotrim`):
- Dataset hierarchy and quotas/reservations:
- Encryption roots, key format/location, and `org.nixos:keystore-sha256` values:
- Snapshot policy:
- Replication/backup targets:
- Last restore drill:

The Disko examples in this directory are fresh-install/recovery specifications only. Do not import them into ordinary runtime activation. Disko formatting modes erase the selected disks; mount-only mode is the appropriate starting point for inspection or repair of an existing layout.
