# Account and permission model

`nas_admin` is the only Authentik group that grants NAS superuser authority. Bootstrap creates one trusted member by default, and an existing superuser may add additional explicitly trusted members. At least one enabled explicit member is required; there is no maximum.

## Default deny

An ordinary account receives **no NAS application capability merely by belonging to `nas_users`**. Managed Services V2 compiles a distinct Authentik capability group for every declared service capability, and the administrator grants access in Authentik by assigning the account to those groups:

| Authentik group | Protected capability |
|---|---|
| `application.copyparty.files` | CopyParty file UI and file-scoped access |
| `application.copyparty.webdav` | CopyParty WebDAV route |
| `application.syncthing.access` | Own Syncthing-device settings and managed personal sync |
| `application.vaultwarden.access` | Vaultwarden web and OIDC access |

These four groups are the ones the default V2 service seed declares; any other application declares its own `application.<service>.<capability>` names. The retired `nas_allow_*` and `nas_deny_*` groups are not V2 authorization rules, and `nas_disabled` disables the account across shared policy.

Authentik application/group bindings should mirror these grants so unauthorized applications are hidden in Authentik as well as denied by Caddy and the backend policy. The proxy checks remain authoritative even if a dashboard binding is accidentally broad.

Ordinary accounts may always manage their password, MFA, and permitted profile fields through Authentik. They can create or use native CopyParty share links only inside volumes and ACLs configured by the administrator.

Ordinary accounts cannot open Cockpit, the global Syncthing UI, or the administrator CopyParty configuration volume.

Cockpit access to `/console` is granted by `nas_admin` or by the `application.cockpit.admin` capability group, which is an alternative to `nas_admin` for the Cockpit route. Either group satisfies the cockpit route authorization check.

## Share policy

CopyParty is the only authority for paths, ACLs, flags, quotas, indexing, and share links. Authentik groups are identity inputs referenced by CopyParty ACLs; they do not generate shares. There is no `nasShareFlags` or `share-*` translation path.

Caddy deletes client-supplied identity headers before invoking Authentik forward authentication. Backend services accept only the trusted headers produced by that path.
