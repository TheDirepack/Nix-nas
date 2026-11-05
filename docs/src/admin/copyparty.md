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

- `/shares`: read access to the share tree for `application.copyparty.files`; administrators retain full access.
- `/shares/users/${u%+application.copyparty.files}`: dynamic per-user volume.
- `/shares/admin/copyparty-config`: administrator-only configuration volume.
- `/tftp`: optional anonymous read-only TFTP volume; an administrator may explicitly enable unauthenticated writes on a tightly trusted provisioning LAN.

Add shared/group volumes directly in CopyParty configuration. Reference Authentik groups with normal CopyParty group ACL syntax.

## Migrating existing volume ACLs

The seed file `00-local-overrides.conf` is created only when absent and is never rewritten afterwards, so an installation that followed the earlier allow-list guidance keeps its old ACLs and its old dynamic-volume expression. Managed Services V2 declares no retired `nas_allow_*` or `nas_deny_*` group, so a volume entry that still names one matches no Authentik group.

To migrate, edit the mutable file through `/shares/admin/copyparty-config` and replace the retired name with the canonical group in both places:

- update each `accs` entry, for example to `r: @application.copyparty.files` (keep `A: @nas_admin` for administrators);
- update each dynamic volume name, for example to `[/shares/users/${u%+application.copyparty.files}]`.

Reload CopyParty afterwards (`systemctl reload copyparty`) and check access as an affected user. Assigning the new Authentik group alone does not restore access while the file still names the retired group.

## Native shares

Native share links are enabled at `/share`. `nas_admin` may administer all shares. Ordinary users can create or use shares only according to their accessible volume's ACLs and share-related flags.
