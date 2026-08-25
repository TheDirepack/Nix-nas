# Security model

## Trust boundaries

- Authentik is authoritative for users, credentials, MFA, groups, and application policy.
- CopyParty is authoritative for volumes, paths, ACLs, flags, quotas, indexing, and native share links.
- Caddy is the only trusted reverse proxy. It deletes client-supplied identity headers before forward authentication.
- Syncthing's global UI is administrator-only; user declarations are limited to an Authentik attribute and reconciled into the reserved `nas-*` namespace.
- Cockpit and privileged appliance commands remain restricted to the trusted administrators.
- KeePassXC is authoritative for machine secrets; runtime material lives under `/run/nas-secrets`.

## KeePass unlock

The KDBX password is entered for each `nas-secrets` operation. It is supplied to `keepassxc-cli` through standard input rather than a command-line argument. Runtime files use restrictive modes and disappear on reboot or `nas-secrets stop`.

## Authentik token separation

The bootstrap token exists only to initialize Authentik. Normal automation should use a dedicated scoped token. `nas-secrets activate` warns when both values are equal, and `nas-secrets check-authentik-token`/`nas-identity-sync verify-token` help verify the migration without printing credentials.

## Superuser policy

`nas_admin` intentionally remains the only Authentik superuser group. The identity synchronizer requires at least one enabled explicit member; one is bootstrapped by default and additional fully trusted members are allowed. Ordinary users do not receive Cockpit, the global Syncthing UI, CopyParty configuration volume, or application administration.

## Default-deny capability authorization

`nas_users` is an identity baseline, not an access grant. Ordinary access requires an explicit Authentik `nas_allow_*` group. Caddy uses the same shared policy implementation for files, WebDAV, Syncthing self-service, Vaultwarden SSO, and AI; matching `nas_deny_*` groups and `nas_disabled` fail closed. Authentik application bindings should mirror these groups for correct dashboard visibility.

## CopyParty authorization

Caddy passes authenticated `Remote-User` and `Remote-Groups` headers only after Authentik forward authentication. The `/shares` route additionally requires `nas_allow_files`, and `/dav` requires `nas_allow_webdav`. CopyParty ACLs remain the final authority for files and shares.

CopyParty flags are not filtered through a custom semantic allowlist because only the trusted administrators can change authoritative configuration. Ordinary users may use native share links only where CopyParty's volume ACLs and share flags allow them.

The project no longer creates root-owned structural share trees or performs custom symlink/path policy for shares. Administrators must configure valid paths in CopyParty and should avoid exposing mutable configuration paths to ordinary users.

## Authentik self-service fields

The bundled flow writes `attributes.nasSyncthingDevices` for the authenticated account and uses a User Write stage configured not to create accounts. This is data declaration, not direct access to the Syncthing API. The reconciler validates identifiers and touches only reserved objects.

## Forward authentication

- Client-provided `Remote-*` and `X-Authentik-*` headers are removed.
- Authentik login and outpost callback paths bypass forward-auth recursion.
- Backend listeners remain loopback/Unix-socket scoped where practical.
- Caddy route authorization and upstream application authorization remain independent layers.

## Managed Services V2 authorization

Managed Services V2 compiles desired state from `/var/lib/nas-control/services.yaml` into native systemd, Caddy, Authentik capability objects, and firewall policy. There is no resident feature controller, feature database, or V1 `nas-feature-control` command. Caddy + Authentik enforce request-time capability checks; V2 only ensures the required `application.<service>.<capability>` objects exist and never assigns users to them.

## Deployment safety

`nas-update` retains:

- sanitized Git environment;
- clean-tree and upstream fast-forward checks;
- release-manifest verification for packaged trees;
- local tests and Nix build validation;
- protected-service readiness checks;
- Nix-generation rollback.

It intentionally does not enforce repository ownership, writable-parent, or repository-path symlink policy.

## Backup sensitivity

Restic contains highly sensitive recovery material, including the KeePass database, identity state, configuration, and private service keys. Protect the repository password separately and restrict repository access.

A Restic repository on the same ZFS pool is not an independent disaster backup. Syncoid replication must target another pool/host to protect against whole-pool loss, and replication credentials should be restricted to the required datasets and receive operations.

## Locked-state recovery boundary

While the protected stack is locked, no browser management endpoint is exposed. Caddy may serve static setup guidance at the trusted-interface HTTPS port, but Cockpit, Authentik, CopyParty, and managed applications remain unavailable until `nas-secrets activate` succeeds. Recovery uses the local console, SSH with a provisioned recovery key, or hardware KVM.

`nas-secrets activate` reads the KeePass password from standard input and never stores it in a URL, argument, environment variable, Nix store path, browser storage, or disk file. The Cockpit privileged API allow-list exposes only `activate-stdin` for this purpose after browser authorization, and only when the protected stack requires it.

Caddy/Authentik are deliberately not dependencies of this path. Authentik `nas_admin` membership does not create a host account, which prevents a compromise of the identity database from automatically becoming cold-boot shell/unlock authority. See [ADR-0001](docs/development/adr-0001-authentik-only-browser-access.md) and [Locked-state unlock](docs/src/locked-unlock.md).
