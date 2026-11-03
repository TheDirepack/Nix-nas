# Applications

A new ordinary user starts with no NAS application access. An administrator assigns only the required `application.<service>.<capability>` groups in Authentik. Membership in `nas_users` is not a grant; `nas_admin` is the trusted administrator bypass.

| Application | Required V2 capability group | What the user can do |
|---|---|---|
| CopyParty | `application.copyparty.files` | Browse personal/shared volumes, upload and download files, and use native share links where CopyParty ACLs allow it. |
| WebDAV | `application.copyparty.webdav` | Connect a WebDAV client to the CopyParty WebDAV endpoint. |
| Syncthing | `application.syncthing.access` | Declare personal devices in Authentik; the NAS reconciles the user's managed sync objects. Users created directly in Authentik must have a personal directory provisioned via `nas-setup account apply` before Syncthing reconciliation. |
| Vaultwarden | `application.vaultwarden.access` | Use the personal Vaultwarden service through Authentik OIDC. |

Use [User settings](settings.md) for password, MFA, profile, and personal Syncthing-device changes.

A link appearing in a portal is not an authorization grant. Caddy and the destination service enforce access independently, and CopyParty remains authoritative for file ACLs, quotas, and share behavior.
