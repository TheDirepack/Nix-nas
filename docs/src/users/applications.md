# Applications

A new ordinary user starts with no NAS application access. An administrator assigns only the required `application.<service>.<capability>` groups in Authentik. Membership in `nas_users` is not a grant; `nas_admin` is the trusted administrator bypass.

| Application | Required V2 capability group | What the user can do |
|---|---|---|
| CopyParty | `application.copyparty.files` | Browse personal/shared volumes, upload/download files and use native share links only where CopyParty ACLs permit. |
| WebDAV | `application.copyparty.webdav` | Connect a WebDAV client to CopyParty's WebDAV endpoint. |
| Syncthing | `application.syncthing.access` | Declare personal devices in Authentik for managed synchronization. |
| Vaultwarden | `application.vaultwarden.access` | Use the Vaultwarden web/client paths protected by V2 and Authentik. |

These are the default deployed-service names, not a fixed allow-list for every V2 app. A disabled or uninstalled service has no available endpoint.

Use [User settings](settings.md) for password, MFA, profile and personal Syncthing-device changes. An administrator manages application-group membership in Authentik, not through the reserved-role `nas-setup account --group` option.

A link appearing in a portal is not an authorization grant. Caddy checks route capabilities and CopyParty enforces native ACLs, quotas and share behavior. The older `nas_allow_*` / `nas_deny_*` rules are not part of V2.
