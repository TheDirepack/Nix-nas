# Account and permission model

`nas_admin` is the only Authentik group that grants NAS superuser authority. Bootstrap creates one trusted member by default, and an existing superuser may add additional explicitly trusted members. At least one enabled explicit member is required; there is no maximum.

## Default deny

`nas_users` is a baseline identity role, **not** an application-access grant. Managed Services V2 generates a distinct Authentik capability group for each declared service capability. An administrator grants access by assigning users to those groups **in Authentik**:

| Authentik group | Protected capability |
|---|---|
| `application.copyparty.files` | CopyParty file UI and file-scoped access |
| `application.copyparty.webdav` | CopyParty WebDAV route |
| `application.syncthing.access` | Personal Syncthing-device settings and managed synchronization |
| `application.vaultwarden.access` | Vaultwarden web/OIDC access |

These are examples from the default V2 service seed. Other applications declare their own `application.<service>.<capability>` groups. A service or capability that is not installed is not an available grant.

The retired `nas_allow_*` / `nas_deny_*` groups do **not** implement V2 authorization. There is no matching-deny-group precedence model: identity-protected routes allow the required capability group or `nas_admin`, after successful Authentik forward authentication. `nas_disabled` marks an account disabled under shared identity policy.

**The account setup CLI manages reserved identity roles, not application grants.** In particular, do not pass `application.*` groups to `nas-setup account apply --group`; it rejects non-role groups. Assign or remove application capabilities using Authentik's group membership administration instead.

V2 creates the capability objects and the appropriate launcher application bindings, but does not assign their members. Caddy checks the effective group membership at request time. The application launcher may hide unauthorized links, but is not a security boundary; a missing or overly broad launcher binding cannot grant Caddy access.

Ordinary accounts may manage passwords, MFA, sessions and permitted profile fields in Authentik. They may use native CopyParty share links only within volumes and ACLs configured by the administrator. Ordinary accounts cannot use administrator-only CopyParty configuration, the global Syncthing UI or Cockpit without `nas_admin`.

## Share policy

CopyParty remains the authority for volumes, paths, ACLs, flags, quotas, indexing, and share links. Its group ACLs refer to Authentik-supplied identity groups, including V2 application capability groups. V2 does not synthesize shares or create a second share authorization policy.

Caddy strips client-supplied identity headers before calling Authentik forward-auth and forwards only trusted identity results to backends. These proxy checks complement, rather than replace, application-native ACLs.
