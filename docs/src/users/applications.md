# Applications

A new user starts with no NAS application access. An administrator grants only the required Authentik `nas_allow_*` groups; matching `nas_deny_*` groups override those grants.

| Application | Required capability | What the user can do |
|---|---|---|
| CopyParty | `nas_allow_files` | Browse personal/shared volumes, upload and download files, and use native share links where CopyParty ACLs allow it. |
| WebDAV | `nas_allow_webdav` | Connect a WebDAV client to the CopyParty WebDAV endpoint. |
| Syncthing | `nas_allow_syncthing` | Declare personal devices in Authentik; the NAS reconciles the user's managed sync objects. |
| AI workspace | `nas_allow_ai` | Use Open WebUI and authorized model endpoints. |
| Vaultwarden | `nas_allow_vault` | Use the personal Vaultwarden service through Authentik OIDC. |

Use [User settings](settings.md) for password, MFA, profile, and personal Syncthing-device changes.

A link appearing in a portal is not an authorization grant. Caddy and the destination service enforce access independently, and CopyParty remains authoritative for file ACLs, quotas, and share behavior.
