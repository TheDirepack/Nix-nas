# CopyParty configuration

CopyParty is the authoritative share-management system. Authentik supplies trusted usernames/groups but does not generate volumes, paths, ACLs, flags, quotas, or share links.

## Mutable configuration

The single authoritative include directory is:

```text
/var/lib/copyparty/user.d/
```

The seed file `00-local-overrides.conf` is created only when absent and remains mutable. It is exposed to `nas_admin` at `/shares/admin/copyparty-config`.

Reload native configuration with CopyParty's control panel or:

```console
systemctl reload copyparty
```

Some global settings require a service restart.

## Seeded volumes

- `/shares`: read access to the share tree for `nas_allow_files`; administrators retain full access.
- `/shares/users/${u%+nas_allow_files}`: dynamic per-user volume.
- `/shares/admin/copyparty-config`: administrator-only configuration volume.
- `/tftp`: optional anonymous read-only TFTP volume; an administrator may explicitly enable unauthenticated writes on a tightly trusted provisioning LAN.

Add shared/group volumes directly in CopyParty configuration. Reference Authentik groups with normal CopyParty group ACL syntax.

## Native shares

Native share links are enabled at `/share`. `nas_admin` may administer all shares. Ordinary users can create or use shares only according to their accessible volume's ACLs and share-related flags.
