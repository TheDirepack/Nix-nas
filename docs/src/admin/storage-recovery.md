# Storage installation and recovery

Storage formatting is deliberately separated from routine NixOS activation. The repository includes reviewed examples and a worksheet, but they are not automatically imported into the live system:

- `installation/disko-os-disk-example.nix`
- `installation/disko-fresh-pool-example.nix`
- `installation/pool-layout.md`

## Before creating or recreating storage

1. Record the intended pool topology and dataset hierarchy.
2. Replace every placeholder with a stable `/dev/disk/by-id/...` path.
3. Confirm that each identifier resolves to the expected physical disk.
4. Inspect the generated destructive commands.
5. Back up all recoverable data.
6. Use formatting only for genuinely new storage.

For an existing pool, use import/mount recovery rather than a fresh-format path.

## Recovery

For pool import, encrypted-storage recovery, boot-device replacement, KeePass restore, Authentik restore, Syncoid replicas, Restic recovery, and post-restore verification, follow the [Recovery runbook](../reference/project-RECOVERY.md).
