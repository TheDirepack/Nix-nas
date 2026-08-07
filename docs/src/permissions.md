# Account and permission model

`nas_admin` is the only Authentik group that grants NAS superuser authority. Bootstrap creates one trusted member by default, and an existing superuser may add additional explicitly trusted members. At least one enabled explicit member is required; there is no maximum.

## Default deny

An ordinary account receives **no NAS application capability merely by belonging to `nas_users`**. The administrator grants access in Authentik by adding the account to one or more explicit groups:

| Authentik group | Capability |
|---|---|
| `nas_allow_files` | Authenticated CopyParty UI and personal-volume template |
| `nas_allow_webdav` | WebDAV route |
| `nas_allow_syncthing` | Own Syncthing-device settings and managed personal sync |
| `nas_allow_vault` | Vaultwarden SSO enrollment/sign-in path |
| `nas_allow_ai` | User AI workspace |

The matching `nas_deny_*` group overrides an allow grant. `nas_disabled` disables the account across shared policy.

Authentik application/group bindings should mirror these grants so unauthorized applications are hidden in Authentik as well as denied by Caddy and the backend policy. The proxy checks remain authoritative even if a dashboard binding is accidentally broad.

Ordinary accounts may always manage their password, MFA, and permitted profile fields through Authentik. They can create or use native CopyParty share links only inside volumes and ACLs configured by the administrator.

Ordinary accounts cannot open Cockpit, the global Syncthing UI, or the administrator CopyParty configuration volume.

## Share policy

CopyParty is the only authority for paths, ACLs, flags, quotas, indexing, and share links. Authentik groups are identity inputs referenced by CopyParty ACLs; they do not generate shares. There is no `nasShareFlags` or `share-*` translation path.

Caddy deletes client-supplied identity headers before invoking Authentik forward authentication. Backend services accept only the trusted headers produced by that path.
