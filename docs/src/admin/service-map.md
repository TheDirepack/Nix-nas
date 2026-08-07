# Configuration and management map

Use this page when you are unsure **where** a setting belongs. Keeping one authority for each concern prevents drift and makes recovery predictable.

| Concern | Authority | Normal interface | Important state |
|---|---|---|---|
| Users, passwords, MFA, groups, app bindings | Authentik | `/identity/` | PostgreSQL and `/var/lib/authentik` |
| Trusted administrators | Authentik `nas_admin` | Authentik Directory | Explicit group membership |
| User application access | Authentik capability groups | Authentik Directory | Group membership |
| File volumes, ACLs, quotas, flags, shares | CopyParty | CopyParty UI/config volume | `/var/lib/copyparty/user.d`, CopyParty DBs |
| User file operations | CopyParty | `/shares/`, `/share/` | ZFS-backed data paths |
| Personal Syncthing devices | Authentik user attribute | `/settings/syncthing` | `attributes.nasSyncthingDevices` |
| Global Syncthing configuration | Syncthing + NAS reconciler | `/syncthing/` | Syncthing config directory |
| Runtime feature modes | NAS feature controller | **NAS Overview** | `/var/lib/nas-control/settings.json` |
| ZFS pools/datasets | ZFS/Sanoid/Syncoid | Cockpit ZFS + CLI | ZFS metadata |
| Boot/appliance backup | Restic | Cockpit action + systemd timer | Restic repository |
| Metrics collection | Telegraf | Declarative Nix configuration | systemd runtime state |
| Metrics history/query | VictoriaMetrics | `/victoriametrics/` | `/var/lib/victoriametrics` |
| Dashboards | Grafana | `/metrics/` | `/var/lib/grafana` |
| Alert evaluation | vmalert | declarative rules | VictoriaMetrics alert state |
| Alert delivery/deduplication | NAS alert router | `/alerts/` | `/var/lib/nas-alert-router/state.json` |
| Notifications | ntfy | `/notifications/` | `/var/lib/ntfy-sh` |
| Network profiles | NetworkManager | Cockpit Networking | NetworkManager profiles |
| Firewall policy | firewalld/nftables | Cockpit Networking / `firewall-cmd` | `/var/lib/nas-firewall` |
| Containers | Podman | Cockpit Podman | Podman storage |
| Virtual machines | libvirt | Cockpit Machines | ZFS VM storage path |
| AI model routing | llama-swap | AI runtime UI | AI config/model tree |
| Model downloads | Hugging Face downloader | admin downloader UI/API | AI model tree |
| UPS | NUT | Cockpit + NUT Web UI | NUT config and boot credential |
| Schedules | systemd timers / Cockpit Scheduler | Cockpit | timer/scheduler state |
| Machine secrets and unlock | KeePassXC + `nas-secrets` | locked-state form / CLI | KDBX + `/run/nas-secrets` |
| Deployment | `nas-update` + NixOS generations | **NAS Overview** / CLI | Git checkout and Nix profiles |
| Documentation | mdBook Cockpit package | **NAS Help** | generated from deployed release |

## Configuration layers

- **NixOS** decides what is installed and establishes safe declarative defaults.
- **Authentik** owns identity and authorization membership.
- **Upstream application UIs** own mutable application-specific settings.
- **NAS Overview** provides status, navigation, reviewed host actions, and locked-state recovery.
- **Generated documentation** is reference material; edit the owning source/configuration instead.
