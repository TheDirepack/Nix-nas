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
| Application lifecycle, runtime, routes, listeners, resources and network policy | Managed Services V2 | **NAS Overview** / `nas-managed-services-control` | `/var/lib/nas-control/services.yaml` |
| Application capability object definitions | Managed Services V2 + Authentik | schema-driven service policy / Authentik | `application.<service>.<capability>` objects; assignments remain Authentik-owned |
| ZFS pools/datasets | ZFS/Sanoid/Syncoid | Cockpit ZFS + CLI | ZFS metadata |
| Boot/appliance backup | Restic + Managed Services V2 resource/job policy | Cockpit action + native systemd timer | Restic repository + `services.yaml` |
| Metrics collection | Telegraf | Declarative Nix configuration | systemd runtime state |
| Metrics history/query | VictoriaMetrics | `/victoriametrics/` | `/var/lib/victoriametrics` |
| Dashboards | Grafana | `/metrics/` | `/var/lib/grafana` |
| Alert evaluation | vmalert | declarative rules | VictoriaMetrics alert state |
| Alert delivery/deduplication | NAS alert router | `/alerts/` | `/var/lib/nas-alert-router/state.json` |
| Notifications | ntfy | `/notifications/` | `/var/lib/ntfy-sh` |
| Host network profiles | NetworkManager | Cockpit Networking | NetworkManager profiles |
| Per-application isolated network/VLAN/egress policy | Managed Services V2 | `services.yaml` / schema-driven editor | `network` or `networkProfiles` in `services.yaml` |
| Firewall policy | firewalld/nftables + V2 projection | Cockpit Networking / `firewall-cmd` for host policy; V2 for application listeners/egress | `/var/lib/nas-firewall` + `services.yaml` |
| Containers | Podman | Cockpit Podman + V2 runtime policy | Podman storage + `services.yaml` |
| Virtual machines | libvirt | Cockpit Machines + V2 runtime policy | ZFS VM storage path + `services.yaml` |
| AI model routing | llama-swap | AI runtime UI | AI config/model tree |
| Model downloads | Hugging Face downloader | admin downloader UI/API | AI model tree |
| UPS | NUT | Cockpit + NUT Web UI | NUT config and boot credential |
| Managed application/job schedules | Managed Services V2 -> native systemd timers | `services.yaml` / Cockpit systemd timer view | V2 desired state plus generated systemd timers |
| Optional non-V2 host schedules | Cockpit Scheduler where configured | Cockpit Scheduler | scheduler state |
| Machine secrets and unlock | KeePassXC + `nas-secrets` | locked-state form / CLI | KDBX + `/run/nas-secrets` |
| Deployment | `nas-update` + NixOS generations | **NAS Overview** / CLI | Git checkout and Nix profiles |
| Documentation | mdBook Cockpit package | **NAS Help** | generated from deployed release |

## Configuration layers

- **NixOS** decides what is installed and establishes safe declarative defaults.
- **Managed Services V2** owns mutable application desired state in `services.yaml` and finitely projects it into native runtime mechanisms.
- **Authentik** owns human identities, groups, capability assignments, passwords, MFA, and application bindings.
- **Upstream application UIs** own mutable application-specific settings that do not belong in cross-cutting V2 policy.
- **NAS Overview** provides status, navigation, reviewed host actions, and locked-state recovery.
- **Generated documentation** is reference material; edit the owning source/configuration instead.
