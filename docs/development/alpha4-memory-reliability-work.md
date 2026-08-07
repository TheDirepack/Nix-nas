# 2.2.0-alpha.4 memory and reliability work

Alpha.4 starts the resource-reduction work without hiding the release-blocking reliability defects found in the Alpha.3 review. The first implementation batch intentionally fixes the critical state/coordinator/recovery defects before taking larger architectural memory risks.

## Implemented in this batch

### Release-blocking reliability

- Corrected coordinated `nas-state export` and `nas-state restore` validation semantics.
- Delegated Cockpit operation ownership to lock-owning workers instead of holding a conflicting API-process lock.
- Made restore-unit selection profile-aware and restored NetworkManager/firewalld before reloading them.
- Restored KeePass with administrator ownership (`adminUser:users`, mode `0600`).
- Made update rollback phase-aware and source-promotion rollback-capable.
- Added deterministic libvirt `nas-zfs` directory-pool creation at the configured VM storage path; installed Cockpit/default-pool selection remains to be qualified.

### Security and execution hardening

- Centralized bounded streaming command execution and process-group timeout cleanup in `nas_common.run_command`.
- Removed the ntfy administrator password from `htpasswd` argv.
- Changed validation HTTP credentials to stdin-backed curl configuration and browser-test password files.
- Corrected degraded operation-root fallback to require/restore `root:nas-operations` ownership and setgid mode.
- State manifests now receive immutable realized-source provenance.

### Memory/resource reductions

- VictoriaMetrics: `-memory.allowedBytes=96MiB` plus `MemoryHigh=128M`.
- Telegraf: baseline collection/flush interval increased from 30 seconds to 60 seconds.
- ntfy: message history moved to SQLite cache storage.
- Syncthing: `GOMEMLIMIT=192MiB`, one connection per generated device, a 16 MiB pending-pull target, disabled scan-progress churn, and weak-hash threshold tuning.
- AI/on-demand services: shorter default model/service idle windows so large optional processes are released sooner.

## Deliberately not claimed complete yet

The larger architectural reductions remain staged behind qualification rather than being forced into the same patch: Authentik 2026.5 packaging/migration, VMUI-as-default dashboard UX, Cockpit-native UPS/model download UIs, Avahi replacement, socket activation of custom helpers, modular libvirt conversion, and optional service replacement experiments.

Several review findings also need deeper architectural work rather than a local patch, including restricting Telegraf SMART privilege to a validated read-only helper, state capture TOCTOU hardening, encrypted sensitive recovery bundles, network deadman rollback, application-native/atomic recovery adapters, independently versioned state adapters, and migration rehearsal/downgrade policy.

## Qualification status

Source-level Python and shell tests can be run in the current environment. Nix evaluation/build, QEMU/native/encrypted VM qualification, official installer/reboot/rollback, and hardware smoke testing require the project release environment and must remain unverified until executed against this exact Alpha.4 artifact.
