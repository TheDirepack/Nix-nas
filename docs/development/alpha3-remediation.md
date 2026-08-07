# 2.2.0-alpha.3 audit remediation

This record covers the source changes made after the two Alpha.2 reviews. It is implementation evidence, not installed-system qualification. Alpha.3 remains source-only until the exact Cockpit build artifact and the Nix/QEMU/installer/browser/hardware gates in the release checklist pass for this revision.

## Runtime authority fixes

- Nested mutations no longer trust `NAS_OPERATION_COORDINATED=1`. `nas-operation-run` creates a random coordination claim bound to the live parent PID, boot ID, process start identity, requested lock classes, and the Linux PID that actually owns each required physical `flock`. Child feature, identity, state, update, setup, and secret operations validate that proof before treating themselves as nested.
- The separate state-tool `NAS_STATE_SKIP_OPERATION_LOCK` escape hatch was removed. Standalone state export/restore takes the appliance-wide coordinator; update-owned state operations use the validated ancestor proof instead.
- Operation reservations use monotonic time for in-boot expiry decisions while retaining wall-clock timestamps for operator diagnostics.
- The degraded root fallback recreates `/run/nas-operations` with mode `2770`, preserving setgid group inheritance expected by the production tmpfiles policy.
- `nas-doctor --deep` checks the operation-root owner/group/mode and warns when legacy or active coordination environment state leaks into an interactive diagnostic context.

## Recovery fixes

- Path authorities now carry code-owned `restoreStrategy`, `owner`, `group`, and `rootMode` metadata. Restoring an authority whose destination root is absent resolves that policy rather than silently recreating the authority as `root:root`.
- Existing heterogeneous subpaths still retain their observed local UID/GID/mode policy. This does **not** make the generic bundle a byte-for-byte filesystem image; ACLs, xattrs, capabilities, hard-link topology, sparse/reflink semantics, and application-native database semantics remain outside the generic path-copy contract.
- State/database helper timeouts create a separate process session and terminate the whole child process group before rollback/recovery proceeds. A regression test verifies a grandchild cannot survive the timeout.
- First-start result files now have bounded age/count retention.
- Corrupt alert-router state is quarantined and surfaced through diagnostics instead of being silently interpreted as an empty deduplication database.

## Protocol and tooling fixes

- Authentik `Retry-After: 0` is floored to the normal retry minimum, avoiding an immediate retry burst. Retry jitter uses a per-call cryptographic random value rather than shared PRNG state.
- Shared `run_command()` now has a bounded default timeout rather than an infinite default.
- Cockpit overview cancellation is handled explicitly, and the future deadline documents its required relationship to the command-probe deadline.
- The adversarial probe suite explicitly rejects plain HTTP health targets on non-loopback addresses.
- Secret transaction phases (`pre-swap`, `post-swap`, `committed`) are documented next to the implementation.
- `cockpit/package.json` participates in the central version check and now matches Alpha.3.
- The repository was formatted with Ruff 0.16.1. `ruff format --check` and `ruff check` both pass on the Alpha.3 candidate. Intentional post-`sys.path` imports are narrowly exempted from E402 only in the bootstrap test/fuzz files that require them.
- Identity-model compatibility re-exports from `nas_identity_sync` are now explicit instead of looking like dead imports to static analysis.

## Validation completed in this source environment

- 29 fast Python test files: 364 tests, with the Hypothesis property tier as the single local dependency skip.
- Maintainer/release groups: 14 tests passed when run in their intended isolated process boundaries. Across those source tiers, 378 Python tests were executed: 377 passed and one dependency-gated property test was skipped locally.
- Cockpit JavaScript: 19/19 tests passed.
- Source security tier: 4/4 checks passed.
- Deterministic boundary fuzz smoke: 250 cases per configured boundary target with the recorded seed; all fuzz unittest targets passed.
- Executable fuzz: all 28 maintainer executable strategies passed.
- Branch coverage: 72.6% aggregate, above the 66% floor; every declared per-module floor passed.
- Ruff 0.16.1: 74/74 Python files formatted; lint passed.
- Version, repository-data, documentation-link, Python-syntax, custom-executable inventory, `mkForce`, static security, Cockpit JSX, shell syntax, and repository-structure checks passed.

## Still open / requires installed-system evidence

- Generic state bundles still lack full filesystem metadata fidelity and authority-specific native adapters for all database/libvirt/application state.
- Restore/network changes still have no independent remote-administration deadman rollback.
- Systemd-owned ZFS lifecycle mutation ordering still requires real NixOS/QEMU proof before further coordinator wrapping.
- The large setup, feature-control, state, and identity orchestration modules still deserve architectural decomposition into typed transaction/adaptor layers.
- The exact Cockpit dependency lock/compiled distribution is still absent from this source-only artifact.
- Nix evaluation and closures, native unencrypted/encrypted NixOS tests, official-ISO installation/reconfiguration/rollback/reboot, real browser authorization/layout/accessibility, ZAP, ZFS recovery drills, and hardware smoke qualification remain unexecuted here.
