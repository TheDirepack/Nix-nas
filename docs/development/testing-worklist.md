# Testing work list

Updated against `be450870` on 2026-11-08. The initial review used `a2d838c9`;
current main already fixes the Python `tests` package collision and includes
live OCI SQLite durability, credential binding, isolation, container recreation,
and quiesced snapshot/clone recovery. Those improvements remain prerequisites.
AI inference and GPU qualification are excluded by the current project scope.

Use [testing.md](testing.md) for qualification commands and
[known-risks.md](known-risks.md) for recovery boundaries. Implementation of a test
does not constitute a passing installed-system run.

## Highest-priority installation gaps

1. **T01 — custom app persistence through install lifecycle.** Added a second
   offline OCI fixture that remains installed through secret stop/reactivation,
   locked reboots, package upgrades, candidate switches, rollback and final
   reboot. Its read-only verifier checks the exact desired revision, service and
   storage declarations, live image/HTTP, dataset mount, data checksum/ownership,
   container-visible data and CPU/memory/PID limits. Native teardown and final
   browser-overlay teardown remove its runtime while retaining data. Require
   native and both installer lanes to pass before closing this item.
2. **T02 — real Cockpit app editing.** Added an installed Chromium flow for
   schema-form save/reconcile, stale edits from a second tab, invalid YAML,
   retained unsaved input and reload/read-back. One browser project owns these
   mutations because all projects share the appliance document. Still open:
   creating a new app entirely through the form and reconnecting during apply.
3. **T03 — dynamically created route authorization.** Added real administrator,
   unrelated-capability and baseline-user checks, followed by Authentik-owned
   grant and revocation. Success requires the app's exact live HTTP response;
   denial requires 403. Revocation uses a fresh login. Still open: disabled
   identities, already-established sessions, and independent-peer direct-port
   probes for custom apps. Existing spoofed-header tests remain required.
4. **T04 — attachments and recovery.** Main already exercises declared data and
   credential mounts, ownership, usable SQLite snapshot restoration and retained
   data after removal. Still open: credential rotation, backup scheduling and
   complete recovery to an empty appliance. Keep control-bundle restore distinct
   from native application-data recovery.
5. **T05 — running-unhealthy update rollback.** Added an update that writes a
   startup witness but serves an HTTP readiness failure. Require the witness,
   readiness-timeout journal, restored exact desired bytes, healthy response and
   unchanged database identity/tasks/metadata/credential. Still open: failed
   compensation and a later safe retry with durable manual-recovery evidence.
6. **T06 — phase-specific health and evidence.** Still open: replace permissive
   early doctor smoke checks with explicit phase-specific warning policy and
   structured per-phase evidence tied to source/frontend/flake/image identities.
   Reconfiguration and final reboot must continue to require successful doctor
   execution; diagnostics must never count as a healthy-system assertion.

## Next workload and failure coverage

7. **T07 — custom builds and native Compose.** Build a tiny Containerfile from
   pinned offline inputs, register the resulting image through V2, and separately
   exercise Compose-provider → Podlet → Quadlet with communicating services,
   attachments and a route. Prove failed build/import preserves the applied
   generation. Decide the supported source-build interface before describing
   image-reference editing as a build service. Use the existing Podman authority.
8. **T08 — other runtime owners.** Add bounded installed exec/Python, source
   Quadlet, job and OCI-session fixtures. Use a separate virtualization-enabled
   profile for libvirt. Prove start/readiness, update, disable, remove and failure
   cleanup through production projections. Verify per-user/session separation.
9. **T09 — coding workspace.** Start with a small coding CLI/job that writes and
   executes a bounded workspace command. Verify persisted ownership, two-user
   isolation and inaccessible host paths. If a browser IDE becomes supported,
   add authenticated assets, WebSocket, reconnect and cleanup qualification.
10. **T11 — network policy from multiple peers.** Probe allowed/denied TCP/UDP,
    egress, host/LAN and cross-app access, including reload and failed policy
    update. Include IPv6 support or explicit rejection. Denial needs reachable
    positive controls so an unavailable peer cannot pass the test.
11. **T12 — limits under load and on-demand races.** The persistence fixture now
    reads actual cgroup limits; bounded memory/PID/CPU workloads remain open.
    Add concurrent wake, idle stop, failed dependency and wake-during-apply tests
    that detect duplicate owners and leaked resources.
12. **T13 — interrupted apply and contention.** Interrupt after durable writes
    and native adapter changes, reboot at selected boundaries and contend with
    secret/update/editor operations. Prove lock release, journal recovery,
    revision consistency and safe retry. Do not blanket-lock arbitrary workloads
    or deadlock protected-target startup.
13. **T14 — real resource failures.** Use a small dedicated filesystem for
    ENOSPC, interrupt a fetch from a local registry, terminate a real child and
    remove a declared mount while exercising its guard. Bound each drill, retain
    diagnostics and inspect surviving generation/credential/artifact state.
    Existing canned-error harness tests do not qualify these outcomes.
    During local qualification, terminating the installer wrapper and its QEMU
    child also emitted `vm_started_by_this_run: unbound variable` from cleanup;
    add a signal regression that preserves the initiating exit and exercises
    cleanup after the install function unwinds.
14. **T16 — stronger test oracles.** Added persistence fault cases for changed
    revisions, declarations, mounts, data, ownership, live image/HTTP, attachments,
    limits and routes, plus strict lock-denial and authorization-response tests.
    Extend the existing [oracle suite](../../tests/test_testing_oracles.py) for
    failed compensation and native removal. Presence/inventory checks remain
    discovery evidence, not runtime qualification.
15. **T17 — Python package resolution.** The explicit `tests/__init__.py` fix is
    already on main. Added a subprocess regression with a competing regular
    `tests` package on the import path; verify discovery and the isolated runner.

T10 (AI inference) and T15 (GPU hardware lanes) are deferred and have no test or
dependency additions in this change.

## Completion rules

Close items only with the required same-source native/browser/installer evidence.
Update [timeout-budget.json](../../tests/vm/timeout-budget.json) for added bounded
work. Keep images, models, VM disks, credentials and reports out of the source
tree. On this host, use the persistent NixOS VM wrapper for evaluation and VM
qualification; do not retry host Nix. Split later heavy fixtures into explicit
profiles instead of extending one unbounded guest script.
