# Testing work list

AI inference and GPU qualification are excluded by the current project scope.

Use [testing.md](testing.md) for qualification commands and
[known-risks.md](known-risks.md) for recovery boundaries. Implementation of a test
does not constitute a passing installed-system run.

## Highest-priority installation gaps

- **T01 — custom app persistence through install lifecycle.** Require native
  and both installer lanes to pass the implemented lifecycle checks described in
  [testing.md](testing.md#4-coverage-regression-gates).
- **T02 — real Cockpit app editing.** Creating a new app entirely through the
  form and reconnecting during apply remain open. Existing editor coverage is
  described in [testing.md](testing.md#4-coverage-regression-gates).
- **T03 — dynamically created route authorization.** Disabled identities,
  already-established sessions, and independent-peer direct-port probes for
  custom apps remain open. Existing spoofed-header tests remain required.
- **T04 — attachments and recovery.** Credential rotation, backup scheduling and
  complete recovery to an empty appliance remain open. Keep control-bundle
  restore distinct from native application-data recovery.
- **T05 — running-unhealthy update rollback.** Failed compensation and a later
  safe retry with durable manual-recovery evidence remain open. Existing healthy
  rollback checks are described in [testing.md](testing.md#4-coverage-regression-gates).
- **T06 — phase-specific health and evidence.** Still open: replace permissive
   early doctor smoke checks with explicit phase-specific warning policy and
   structured per-phase evidence tied to source/frontend/flake/image identities.
   Reconfiguration and final reboot must continue to require successful doctor
   execution; diagnostics must never count as a healthy-system assertion.

## Next workload and failure coverage

- **T07 — custom builds and native Compose.** Build a tiny Containerfile from
   pinned offline inputs, register the resulting image through V2, and separately
   exercise Compose-provider → Podlet → Quadlet with communicating services,
   attachments and a route. Prove failed build/import preserves the applied
   generation. Decide the supported source-build interface before describing
   image-reference editing as a build service. Use the existing Podman authority.
- **T08 — other runtime owners.** Add bounded installed exec/Python, source
   Quadlet, job and OCI-session fixtures. Use a separate virtualization-enabled
   profile for libvirt. Prove start/readiness, update, disable, remove and failure
   cleanup through production projections. Verify per-user/session separation.
- **T09 — coding workspace.** Start with a small coding CLI/job that writes and
   executes a bounded workspace command. Verify persisted ownership, two-user
   isolation and inaccessible host paths. If a browser IDE becomes supported,
   add authenticated assets, WebSocket, reconnect and cleanup qualification.
- **T11 — network policy from multiple peers.** Probe allowed/denied TCP/UDP,
    egress, host/LAN and cross-app access, including reload and failed policy
    update. Include IPv6 support or explicit rejection. Denial needs reachable
    positive controls so an unavailable peer cannot pass the test.
- **T12 — limits under load and on-demand races.** Bounded memory/PID/CPU
    workloads remain open beyond the existing cgroup-limit checks.
    Add concurrent wake, idle stop, failed dependency and wake-during-apply tests
    that detect duplicate owners and leaked resources.
- **T13 — interrupted apply and contention.** Interrupt after durable writes
    and native adapter changes, reboot at selected boundaries and contend with
    secret/update/editor operations. Prove lock release, journal recovery,
    revision consistency and safe retry. Do not blanket-lock arbitrary workloads
    or deadlock protected-target startup.
- **T14 — real resource failures.** Use a small dedicated filesystem for
    ENOSPC, interrupt a fetch from a local registry, terminate a real child and
    remove a declared mount while exercising its guard. Bound each drill, retain
    diagnostics and inspect surviving generation/credential/artifact state.
    Existing canned-error harness tests do not qualify these outcomes.
    During local qualification, terminating the installer wrapper and its QEMU
    child also emitted `vm_started_by_this_run: unbound variable` from cleanup;
    add a signal regression that preserves the initiating exit and exercises
    cleanup after the install function unwinds.
- **T16 — stronger test oracles.** Extend the existing
  [oracle suite](../../tests/test_testing_oracles.py) for failed compensation and
  native removal. Presence/inventory checks remain discovery evidence, not
  runtime qualification.

T10 (AI inference) and T15 (GPU hardware lanes) are deferred.

## Completion rules

Close items only with the required same-source native/browser/installer evidence.
Update [timeout-budget.json](../../tests/vm/timeout-budget.json) for added bounded
work. Keep images, models, VM disks, credentials and reports out of the source
tree. Split later heavy fixtures into explicit profiles instead of extending
one unbounded guest script.
