# First start

First start uses a dedicated browser setup application at `/setup/`. It is separate from Cockpit and is authenticated by a disposable bootstrap Authentik/KeePass trust domain.

The bootstrap trust domain exists only so an unconfigured appliance cannot be claimed anonymously over the network. On first boot the appliance creates an installation-unique bootstrap KDBX and random Authentik bootstrap credentials. The `akadmin` password is displayed on the local console/KVM and is not a universal default. The temporary Linux `nas-bootstrap` principal is locked and has no password login.

Nothing from the bootstrap KDBX is copied or promoted into the finished appliance. Setup creates a fresh permanent trust domain and destroys the bootstrap runtime only after the replacements are verified.

## Setup flow

1. Boot the appliance and read the installation-unique `akadmin` password from the local console or hardware KVM.
2. Sign in through Authentik and open `https://<host>/setup/`.
3. Review the non-secret storage/V2 plan and its digest.
4. Choose a new, currently nonexistent Linux administrator username.
5. Choose the Linux administrator password, permanent KeePassXC master password, and Authentik administrator password. The wizard may explicitly reuse the Linux password for KeePassXC and/or Authentik, but both reuse choices default off.
6. Passwords are checked with zxcvbn and a 15-character minimum. The setup service also checks the HIBP range API when it is reachable; an offline HIBP service does not block setup. Future Linux password changes use libpwquality/PAM and future Authentik password changes use Authentik's native password policy.
7. Confirm the exact block-device list and any destructive pool creation.
8. Submit setup. The browser receives a random per-job capability used only to poll that job and request the final reboot after the bootstrap Authentik database is retired.

The setup API listens only on a root-owned Unix socket. Caddy owns public HTTPS and Authentik authentication. Browser-supplied identity headers are stripped before trusted Authentik identity headers are reconstructed.

## Permanent trust domain

After authenticated submission, the finite setup job:

1. verifies the disposable bootstrap authority is healthy without using the user's permanent KeePass password;
2. selects a fresh root-filesystem permanent runtime;
3. creates one permanent `/var/lib/nas-secrets/NAS.kdbx` using the user-supplied KeePass master password and reopens it to verify the password;
4. generates all permanent machine secrets from scratch in that database, including the native OpenZFS encryption key and permanent Authentik/PostgreSQL/service credentials;
5. creates the chosen Linux administrator only if that username does not already exist;
6. creates or imports the explicitly confirmed encrypted ZFS storage using native OpenZFS key validation;
7. starts the permanent root-hosted PostgreSQL/AuthentiK/control plane;
8. creates the permanent Authentik administrator and provisions a restricted steady-state automation token;
9. initializes the mutable Managed Services V2 authority on encrypted ZFS and reconciles the requested application state;
10. verifies the replacement Linux, Authentik, Caddy, storage, and V2 authorities;
11. removes the temporary Authentik setup application, deletes `akadmin`, verifies the bootstrap token is rejected, removes `nas-bootstrap`, and deletes the entire bootstrap runtime; and
12. writes the password-free completion state only after bootstrap retirement succeeds.

Bootstrap retirement is fail-closed. If a replacement authority or retirement step cannot be verified, setup remains incomplete and reports the failed stage for recovery.

## Storage boundary

The root filesystem contains only the control plane required before encrypted ZFS is available: NixOS/V2 implementation code, Caddy base state, Authentik and its PostgreSQL database, the permanent KDBX, setup/recovery metadata, and ZFS unlock machinery.

Mutable V2 desired state, V2 generations/transactions, application configuration/state, containers, VMs, and user data live on encrypted ZFS. There is no root-side fallback copy of the V2 desired-state authority.

The ZFS key is a native random 256-bit key because OpenZFS raw/hex keys are exactly 32 bytes. The project does not add a custom key fingerprint or secondary verifier: after KeePassXC is unlocked, the key is staged privately under `/run`, `zfs load-key` validates it, the datasets are mounted, and V2 can reconcile.

## Resume behavior

Setup is journaled and idempotent. A retry supplies the human passwords again and validates real postconditions rather than comparing a password-derived verifier. Existing permanent KDBX state is reopened; it is never silently overwritten. A secret already generated and consumed by a permanent component is reused from the permanent KDBX on resume rather than independently regenerated.

A stage marked `manual-recovery-required` must be repaired explicitly before retrying. Password-changing stages require explicit confirmation before reapplying a human password.

## Recovery and backups

The permanent KeePass master password belongs to the user and is never stored by Nix-nas. Losing that password prevents recovery from the KDBX, so store it in an independent recovery location.

The root/control-plane Restic backup includes the encrypted permanent KDBX and a consistent Authentik PostgreSQL dump while excluding `/run`, caches, raw PostgreSQL files, and the mounted ZFS tree. The ZFS recovery domain is backed up as the complete encrypted ZFS hierarchy using native raw encrypted replication. This keeps root/control-plane recovery separate from the encrypted V2/application data domain.

A bare-metal recovery restores the root/control-plane backup, opens the restored KDBX with the user's master password, retrieves the native ZFS key, restores/imports the encrypted ZFS hierarchy, and then lets V2 reconcile from its restored ZFS authority.

## Security notes

- There is no universal first-boot password.
- `/setup/` is never an anonymous administrator-claim endpoint.
- The permanent Linux username is user-selected but must not already exist.
- KeePassXC, Linux, and Authentik passwords are independent unless the user explicitly selects a reuse toggle.
- Machine credentials are random and are not subjected to human-password strength rules.
- Authentik owns human browser identities, passwords, MFA, groups, and application assignments after setup.
- Caddy is the public HTTP/TLS boundary; HTTP applications bind to loopback or Unix sockets.
- The steady-state Authentik automation token is intentionally unable to create users or reset passwords.
