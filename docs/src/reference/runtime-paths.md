# Runtime paths, ownership, and backup coverage

| Path | Purpose | Persistence/backup |
|---|---|---|
| `/run/nas-secrets` | Decrypted runtime service material | tmpfs/runtime only; rebuilt from KeePassXC |
| `/var/lib/nas-control-plane/nas-secrets/NAS.kdbx` | Default boot-side KeePassXC source database | Back up independently; it must remain available before ZFS unlock |
| `/var/lib/nas-control-plane/authentik/outpost-token` | Least-privilege embedded-outpost token used to gate `/unlock/` while locked | Root-only; refreshed from KeePass by each activation |
| `/run/nas-authentik/environment` | Per-boot Authentik secret key for the locked sign-in layer | tmpfs; the KeePass environment overrides it after unlock |
| `/run/nas-unlock/unlock.sock` | `nas-unlock-api` socket reachable only by Caddy and root | Proxied only by the locked Caddy configuration |
| `/var/lib/authentik` | Authentik files | Restic; PostgreSQL also requires database backup/restore |
| PostgreSQL `authentik` DB | Identities, groups, flows, applications | Consistent database backup required |
| `/var/lib/copyparty/user.d` | Authoritative mutable CopyParty configuration | Restic |
| CopyParty databases | Shares, sessions, indexes where configured | SQLite-consistent Restic staging |
| `<zfsRoot>/shares` | User and shared file data | ZFS snapshots and Syncoid; not duplicated by Restic |
| `/var/lib/syncthing` | Syncthing identity and configuration | Restic |
| `/var/lib/nas-control` | Feature-mode state | Restic |
| `/var/lib/victoriametrics` | Metrics history | Disposable or protect via dataset/backup policy |
| `/var/lib/grafana/grafana.db` | Mutable Grafana dashboard/UI state | Restic when enabled |
| `/var/lib/ntfy-sh` | Notification state | Restic when enabled |
| `<zfsRoot>/virtual-machines` | VM images | ZFS snapshots/Syncoid |
| `/boot`, `/etc/nixos`, `/etc/ssh`, machine identity | Boot and reconstruction state | `nas-boot-system` Restic job |

A Restic repository on the same ZFS pool protects against boot-device failure and accidental file loss but not total pool loss. Syncoid or another independent off-pool copy is required for that failure mode.
