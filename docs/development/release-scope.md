# First appliance release scope

The product is a GUI-first NAS for a Linux administrator. Browser clients collect
input, invoke installed CLI operations and render their results. CLI commands own
authorization, validation, locking, plans, execution, rollback and status. Native
services retain their existing authorities. Browser affordances never authorize
an action. Recovery-terminal access remains necessary while the appliance is locked.

The first install-ready designation requires one supported end-to-end appliance
path: reviewed host installation, guarded ZFS setup, administrator and ordinary
user access, file sharing, locked reboot/unlock, independent backup and restore,
guarded update/rollback and a trusted custom OCI application. Use the existing
[release checklist](release-checklist.md) to retain evidence; this scope document
does not assert that those gates have passed.

## Operator acceptance

- Complete setup in the canonical browser wizard. API, detached worker and trusted
  CLI integration must reject the same malformed administrator/secret inputs.
  Reconnect to the actual operation; a lost browser session does not cancel it.
- Prove ordinary-user file isolation and capability grant/revocation on the real
  Authentik/Caddy/CopyParty path. Keep local PAM recovery authority separate.
- Reboot locked, activate secrets through the recovery plane, and recover the
  same data, identities and custom application without manual runtime repair.
- Replace the boot device while retaining the data pool. Restore the exact host
  configuration, independent KeePass material, identity database/native dumps,
  application artifacts and data using their owning recovery mechanisms. Prove
  file and application access after the replacement. Run on disposable media.
- Demonstrate independent backup restoration; same-pool snapshots alone do not
  qualify disaster recovery. `nas-state` remains a small control-config bundle.
- Reject an unhealthy candidate and retain desired revision, runtime and data.
  A database migration needs a compatible native recovery plan; a Nix generation
  rollback does not establish database compatibility.
- Display unavailable observations explicitly. Process activity, readiness,
  backup completion and successful restoration are distinct observations.

## Optional capabilities

Keep existing V2 adapters and optional profiles available to development. Claim
support only for the runtime/profile combinations with matching lifecycle,
storage, authorization, failure and recovery evidence. Adding an application
should supply a V2 definition and native artifacts rather than an app-specific
controller or another settings database.

Treat OCI applications as administrator-trusted until a stronger isolation
profile is qualified. Untrusted coding/agent execution, delegated tenant
lifecycle and rootless/user-namespace guarantees are outside the initial claim.
AI inference and GPU qualification remain deferred.

Remote network-affecting state restore is outside the initial qualified claim
until an independent timed-confirmation rollback path is implemented and VM
tested. The CLI's explicit disconnection acknowledgement is a guardrail for
out-of-band recovery, not an automatic rollback or proof of connectivity.

## Maintenance and resource qualification

Measure the minimum supported host's locked boot, unlocked idle, normal file
activity, backup/restore and update build separately. Browser/build tools in the
test VM are not a measurement of appliance runtime requirements. Keep optional
telemetry and workloads identifiable rather than deriving a host minimum from CI.

For every upstream patch, record the boundary it repairs, the tests that protect
it and a concrete removal condition in [dependencies.md](dependencies.md).
Re-evaluate patches during dependency updates; do not weaken runtime policy or
scanner findings merely to reduce qualification failures.

## Next qualification work

Keep these in priority order and attach evidence to the existing release gates:

1. Run the installed V2 lifecycle and browser cases on the same source/frontend
   artifact: persistent custom OCI application, rejected readiness candidate,
   administrator-only mutation and ordinary-user access denial. Source fixtures
   and mocked browser tests cannot establish installed behavior.
2. Automate a boot-device replacement drill with independent secrets, identity
   database recovery and application-native backup restoration. Verify actual
   user access and data after recovery rather than accepting service startup.
3. Implement network rollback owned by the CLI with a persistent deadline and
   independent reachability confirmation. Test client loss, process crash,
   restart and failed rollback before enabling remote network restore.
4. Qualify a rootless or equivalent OCI isolation profile before untrusted code
   or delegated users can create workloads. Include host-path, socket, device,
   cross-application network and privilege-escalation negative cases.
5. Prove coordinator-safe ordering for direct storage lifecycle mutations and
   shared-state systemd jobs, including competing operations and locked boot.
6. Measure minimum-host resources and retire upstream patches only after the
   corresponding unpatched installed regressions pass.
