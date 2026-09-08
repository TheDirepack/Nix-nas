# Runtime paths, ownership, and backup coverage

| Path | Purpose | Persistence/backup |
|---|---|---|
| `/run/nas-secrets` | Decrypted runtime service material | tmpfs/runtime only; rebuilt from KeePassXC |
| `/var/lib/nas-control-plane/nas-secrets/NAS.kdbx` | Default boot-side KeePassXC source database | Back up independently; it must remain available before ZFS unlock |
| `/var/lib/authentik` | Authentik files | Restic; PostgreSQL also requires database backup/restore |
| PostgreSQL `authentik` DB | Identities, groups, flows, applications | Consistent database backup required |
| `/var/lib/copyparty/user.d` | Authoritative mutable CopyParty configuration | Restic |
| CopyParty databases | Shares, sessions, indexes where configured | SQLite-consistent Restic staging |
| `<zfsRoot>/shares` | User and shared file data | ZFS snapshots and Syncoid; not duplicated by Restic |
| `/var/lib/syncthing` | Syncthing identity and configuration | Restic |
| `/var/lib/nas-control` | Feature-mode state | Restic |
| `/var/lib/victoriametrics` | Metrics history | Disposable or protect via dataset/backup policy |
| `/var/lib/grafana` | Dashboard/UI state | Restic when enabled |
| `/var/lib/ntfy-sh` | Notification state | Restic when enabled |
| `<zfsRoot>/virtual-machines` | VM images | ZFS snapshots/Syncoid |
| `<zfsRoot>/ai` | AI models and configuration | ZFS snapshots/Syncoid according to policy |
| `/boot`, `/etc/nixos`, `/etc/ssh`, machine identity | Boot and reconstruction state | `nas-boot-system` Restic job |

A Restic repository on the same ZFS pool protects against boot-device failure and accidental file loss but not total pool loss. Syncoid or another independent off-pool copy is required for that failure mode.
