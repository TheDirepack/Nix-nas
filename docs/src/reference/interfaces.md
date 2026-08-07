# Web interfaces and endpoints

All normal browser routes use `https://<nas-hostname>.local`. The direct Cockpit recovery endpoint uses port `9092` and is restricted to trusted interfaces by firewalld.

| Path | Audience | Authority / purpose |
|---|---|---|
| `/` | Authenticated users | Lightweight Caddy-rendered application launcher; links are filtered but are not the authorization boundary. |
| `/identity/` | Users/admins | Authentik account, MFA, session, directory, provider, and application administration. |
| `/settings/` | Users | Authentik native user settings. |
| `/settings/syncthing` | `nas_allow_syncthing` | Authentik flow for the signed-in user's device declarations. |
| `/shares/` | `nas_allow_files` or admin | CopyParty file browser and native share operations. |
| `/shares/admin/copyparty-config/` | `nas_admin` | Authoritative mutable CopyParty configuration. |
| `/share/…` | Share recipient | CopyParty native token/password share links; authorization is controlled by CopyParty. |
| `/dav/` | `nas_allow_webdav` | CopyParty WebDAV endpoint. |
| `/syncthing/` | `nas_admin` | Global upstream Syncthing UI. |
| `/vault/` | `nas_allow_vault` | Vaultwarden web vault and clients. |
| `/ai/` | `nas_allow_ai` | Open WebUI. |
| `/ai/models/` | `nas_admin` | Model downloader interface when enabled. |
| `/metrics/` | `nas_admin` | Grafana dashboards. |
| `/victoriametrics/` | `nas_admin` | VictoriaMetrics VMUI and PromQL-compatible APIs. |
| `/alerts/` | `nas_admin` | Read-only NAS alert-router status and delivery state. |
| `/notifications/` | Native ntfy credentials | ntfy UI and client API. |
| `/console/` | Local Cockpit/PAM admin | Cockpit through Caddy after unlock. |
| `https://<host>:9092/console/` | Local Cockpit/PAM admin | Locked-state Cockpit and web unlock; does not depend on Authentik/Caddy. |
| `/docs/` (Cockpit navigation item) | Cockpit admin | Searchable manual generated for the deployed release. |

Routes compiled out by disabled Nix options do not exist. On-demand services may start when an authorized request arrives; authorization-only capability checks do not themselves grant a feature or application permission.
