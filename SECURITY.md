# Security model

## Trust boundaries

- Authentik is authoritative for human browser identities, passwords, MFA, groups, and application assignments.
- Caddy is the only public HTTP/TLS reverse proxy. HTTP applications bind to loopback or Unix sockets and do not implement a second public TLS boundary.
- CopyParty is authoritative for its volumes, ACLs, quotas, flags, indexing, and native share links.
- KeePassXC is authoritative for permanent machine secrets. Runtime secret material is staged under `/run` with restrictive ownership/modes.
- OpenZFS is authoritative for encrypted-dataset key validation. NixOS NAS does not add a custom key fingerprint or secondary encryption protocol.
- Managed Services V2 is authoritative for managed-application desired state only after encrypted ZFS is mounted.

## First-run trust

The standalone `/setup/` application is never anonymous. Before permanent secrets exist, an installation-unique disposable bootstrap KDBX holds only the temporary Authentik secret key, bootstrap token, and random `akadmin` password. The password is shown on the local console/KVM. The temporary Linux `nas-bootstrap` principal is locked, nologin, and has no password authentication.

The bootstrap KDBX is not promoted. Authenticated setup creates a fresh permanent KDBX using the user's supplied master password, verifies that database by reopening it, and generates every permanent machine credential from scratch. Setup completion is fail-closed until the permanent Linux administrator, Authentik administrator, Caddy path, storage, and V2 path are verified and the bootstrap Authentik authority/account/runtime are removed.

The permanent Linux administrator username is user-selected but must not already exist. Setup never changes the password or groups of an existing local account.

## Password policy

Human passwords entered during setup are validated by the shared `nas-password-quality` service using zxcvbn with a 15-character minimum and contextual inputs. The HIBP range API is checked when reachable; a known-breached password is rejected while an unavailable breach service does not prevent offline setup. Setup-created Authentik users use the same validator before mutation.

The wizard has separate Linux, KeePassXC, and Authentik password fields. Reusing the Linux password for KeePassXC and/or Authentik requires separate explicit opt-in toggles, both off by default.

After setup, Linux password changes use PAM/libpwquality and Authentik password changes use Authentik's native password policy with the same effective minimum zxcvbn score and HIBP rejection. Machine-generated secrets are random and are not evaluated as human passwords.

The permanent KeePass master password is never persisted by NixOS NAS. `keepassxc-cli` receives it on standard input when the real KDBX must be opened; setup journals contain no password-derived verifier.

## Authentik authority separation

The temporary bootstrap token performs only first-run mutations. Setup provisions a separate non-expiring `nas-automation` service-account token for steady state, verifies that it can read users/groups, and explicitly proves that user creation and password-reset operations return HTTP 403 before bootstrap retirement.

The steady-state role contains only `authentik_core.view_user` and `authentik_core.view_group`. Managed Services V2 uses Authentik blueprints for capability/application projections and never assigns users to capability groups.

Authenticated Authentik API requests refuse redirects and origin changes so bearer tokens cannot be forwarded to a different origin. Error handling must not print token values or password-bearing request bodies.

## Caddy and browser authentication

Caddy strips client-provided `Remote-*` and `X-Authentik-*` headers before Authentik forward authentication, then reconstructs trusted identity headers from the Authentik response. Login/outpost callback paths bypass forward-auth recursion only where required by Authentik.

During first-run, Caddy authenticates `/setup/` and proxies `/setup/api/*` to a private Unix socket. The setup API independently accepts only the bootstrap administrator identity. Once the bootstrap Authentik database is retired, the browser uses a random per-job capability only to poll the already-running setup job and request its final reboot; that capability cannot start another setup transaction.

After setup, Caddy + Authentik enforce request-time application capability checks. Cockpit's shared local-session bridge is reachable only on host loopback behind the Caddy/AuthentiK administrator route; the default Cockpit socket/service are disabled.

## Root and encrypted-ZFS boundary

The root filesystem contains the control plane required before encrypted ZFS is available: NixOS and V2 implementation code, Caddy base state, Authentik and its PostgreSQL database, the permanent KDBX, setup/recovery metadata, and ZFS unlock machinery.

Encrypted ZFS contains mutable V2 desired state (`services.yaml`), generations/transactions, application configuration/state, containers, VMs, shares, and user data. There is no root-side fallback desired-state copy.

The ZFS encryption key is a native random 256-bit key because OpenZFS raw/hex wrapping keys are exactly 32 bytes. After KeePassXC unlock, the key is staged privately under `/run`; `zfs load-key` validates it and the key is removed again on lock.

## Managed Services V2 runtime boundaries

V2 compiles desired state into native systemd, Podman/Quadlet/Compose, libvirt, Caddy, Authentik blueprint, and firewalld projections. Generated argument lists are not shell strings. Direct Quadlet sources reject source keys that would bypass V2-managed network, mount, device, secret, or sandbox policy. Firewalld reconciliation computes a complete desired NAS-owned policy and removes stale NAS-owned rules rather than accumulating permissions.

Administrators may deliberately choose runtime-native/inherited policy where the schema exposes that choice. Such native source files are trusted administrator input and are not treated as untrusted user content.

## Backup and recovery sensitivity

The root/control-plane Restic backup contains highly sensitive encrypted recovery material, including `NAS.kdbx`, Authentik state, host configuration, and a consistent PostgreSQL dump. It explicitly excludes `/run`, live PostgreSQL pages, caches, restore scratch space, and the mounted ZFS tree. Restic password/repository files must be regular root-owned files with no group/other permissions; backup and restore verification fail closed on unsafe credential files.

The Restic repository password is a separate recovery credential and needs an independent offline copy. Do not make the only copy an entry inside `NAS.kdbx`, because the KDBX is itself recovered from that Restic repository.

The complete ZFS recovery domain uses native raw encrypted ZFS replication (`zfs send -w` via Syncoid) so V2/application data remains encrypted in transit/storage at the ZFS layer. Root Restic recovery and full encrypted ZFS replication are complementary domains and should normally use storage independent of the source pool.

## Locked-state recovery

After normal setup, the browser stack is not the cold-boot root of trust. The user-known KeePass password and local host administrator/out-of-band console form the recovery boundary. The system opens the root-hosted KDBX, stages the native ZFS key, loads/mounts encrypted ZFS, and only then allows V2 to reconcile managed applications.

Keep independent recovery copies of the KeePass master password, Restic repository password, and any remote-replication credentials required to reach the backup target.
