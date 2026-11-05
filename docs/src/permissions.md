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

These four are the ordinary-user access groups of the default V2 seed and are not the whole capability set; the Syncthing and Vaultwarden groups exist only while `nas.syncthing.enable` and `nas.vaultwarden.enable` are enabled. The seed also declares an administrator capability group per application (below), and any service or capability added to `services.yaml` declares its own `application.<service>.<capability>` names. The retired `nas_allow_*` and `nas_deny_*` groups are not V2 authorization rules, and `nas_disabled` disables the account across shared policy.

Authentik application/group bindings should mirror these grants so unauthorized applications are hidden in Authentik as well as denied by Caddy and the backend policy. The proxy checks remain authoritative even if a dashboard binding is accidentally broad.

Ordinary accounts may always manage their password, MFA, and permitted profile fields through Authentik. They can create or use native CopyParty share links only inside volumes and ACLs configured by the administrator.

Administrator-only surfaces are not implied by the ordinary-user groups: the seeded CopyParty ACL for `/shares/admin/copyparty-config` admits `nas_admin` only, and the global Syncthing UI requires `application.syncthing.admin` or `nas_admin`.

Cockpit is not reserved to `nas_admin` alone: the `/console` route grants access to `application.cockpit.admin` or `nas_admin`. Every V2 identity route accepts `nas_admin` in addition to its documented capability group; the capability group never replaces that bypass.

## Administrator capabilities

The default V2 seed declares one administrator capability group for each application it includes:

| Administrator capability group | Route it satisfies |
|---|---|
| `application.copyparty.admin` | `/shares/admin` route check; the seeded configuration-volume ACL still admits only `nas_admin` |
| `application.syncthing.admin` | `/syncthing` global Syncthing UI |
| `application.vaultwarden.admin` | `/vault/admin` |
| `application.cockpit.admin` | `/console` Cockpit |

Membership in these groups is an Authentik assignment like any other capability; CopyParty ACLs remain the authority for file access.

## Share policy

CopyParty is the only authority for paths, ACLs, flags, quotas, indexing, and share links. Authentik groups are identity inputs referenced by CopyParty ACLs; they do not generate shares. There is no `nasShareFlags` or `share-*` translation path.

Caddy deletes client-supplied identity headers before invoking Authentik forward authentication. Backend services accept only the trusted headers produced by that path.
