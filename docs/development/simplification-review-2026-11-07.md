# Simplification review — 2026-11-07

Reviewed the current setup, Cockpit API, and native systemd reconciliation
surfaces against main at `caffd043`. This is a focused maintenance review;
installed appliance and VM qualification remain separate gates.

## Changes

- Systemd reconciliation repeated runtime-link validation, replacement, and
  empty drop-in directory cleanup across activation, stale-link removal, and
  rollback. These paths now use one `_update_links` operation. Transaction
  ordering, target validators, ownership checks, snapshots, and transient-session
  recovery remain in their existing owners. A restart-failure test verifies
  restoration of systemd and Quadlet links and cleanup of a newly introduced
  drop-in, including preservation of an unrelated local drop-in.
- Setup provisioning and readiness repeated personal-share eligibility and
  path construction. Both now consume `_personal_share_paths`; strict boolean
  activation, guest exclusion, command order, and symlink rejection are covered
  by behavior tests.
- Cockpit source and update operations maintained separate allow-lists alongside
  their command maps. Map membership now validates the operation, preserving
  rejection before filesystem access and subprocess execution.
- The test suite imports shared helpers through `tests.*` but previously relied
  on an implicit namespace package. A system-installed regular package named
  `tests` could intercept those imports. An explicit package initializer keeps
  these imports local without interpreter-path workarounds.

## Follow-up opportunities

- `nas_cockpit_api.py` combines the privileged Cockpit CLI with the setup Unix
  HTTP transport and capability lifecycle. Extracting the transport could make
  those boundaries easier to review, but it needs explicit dependencies for
  capability state, locking, peer checks, and operation dispatch. Keep the
  fixed CLI command allow-list explicit; replacing it with a callback framework
  solely to shorten the module would add indirection.
- The test development shell in `flake.nix` omits `defusedxml`, although
  `nas_v2_libvirt.py` imports it unconditionally and the packaged V2 XML runtime
  includes it. A clean Python test environment without it fails to import the
  compiler/application test graph. Align the development dependency list with
  the packaged runtime and verify the shell through the VM Nix path. This is a
  development-environment gap; the installed XML runtime already declares it.

These changes reuse existing functions and registries. None of the reviewed
duplication requires a new external framework or another desired-state store.

## Existing work

The connected GitHub review found no open PRs at review time. The existing
[delegated application API issue](https://github.com/TheDirepack/Nix-nas/issues/139)
should reuse the current revision locks and lifecycle authority. The
[route host-port collision issue](https://github.com/TheDirepack/Nix-nas/issues/140)
is separate network work; this refactor does not change route publication.
Runtime, connectivity, durability, and graphical-session qualification remain
tracked in issues #141–144 and #104. These review findings do not close those
issues or replace their installed evidence.
