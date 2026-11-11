# Maintenance, service policy, and updates

Use the NAS Cockpit page for routine maintenance. It exposes only fixed, reviewed backend operations; it is not a general root shell.

## Service policy

Managed Services V2 applications can expose one or more runtime modes:

- **Off** — keep the managed workload stopped and remove its V2-owned active exposure policy.
- **On demand** — acquire the native V2 systemd lease after authorized access and release it after the configured idle period.
- **Always on** — keep the managed daemon resident.

`/var/lib/nas-control/services.yaml` is the only mutable application desired-state authority. The finite V2 compiler validates dependencies/readiness and projects lifecycle into native systemd units, timers, targets, and drop-ins; there is no resident feature controller or idle reaper. Caddy + Authentik perform request-time authorization before the socket-activated wake helper acquires an on-demand lease.

NixOS still decides which native platform services and packages are installed. VictoriaMetrics remains resident for continuous history; Grafana can sleep independently.

## Maintenance actions

Depending on installed services, Cockpit can run health checks, identity validation, snapshots, ZFS scrub, backup, replication, Syncthing reconciliation, protected-stack restart, and update workflows.

For direct diagnosis, use the generated command reference and systemd journal rather than bypassing the fixed action boundary. Use `nas-managed-services-control status` to compare V2 requested/effective lifecycle state with native unit state.

For offline checks before installation or while debugging, use `nas-v2 validate`, `nas-v2 effective`, and `nas-v2 plan` with `--spec`, `--schema`, and `--platform` overrides as needed. `nas-v2 apply` delegates to the same finite reconciliation entry point used by systemd.

## Rejected application updates

Saving an always-on application's definition in Cockpit Services runs its declared
readiness probes after activating an affected runtime. Persistent-daemon
readiness budgets are limited to 150 seconds; longer budgets are rejected during
projection validation before runtime activation. The generated gate includes
a finite startup allowance for probe and process overhead. Affected gates run
together in one systemd job. Before arming rollback, the command derives a finite
budget from the desired dependency graph, declared readiness deadlines and prior
owned units. It includes allowances for ordered dependency startup, sequential
owner activation, compensation and other projections. The CLI and Cockpit wait
beyond that same transaction budget so they can report its result. Large service
graphs can therefore take longer before the rollback guard fires. A desired edit
after budgeting rejects the transaction before compilation and runtime mutation;
retry the edit after the current operation finishes. A probe failure rejects
the apply. The controller attempts to restore the previous generation's runtime
links, previously active owners, and recorded state. It reports failed or
uncertain recovery explicitly; a rejected update must not be treated as healthy
merely because the previous definition is visible again. Transient sessions
that were terminated may need operator recovery.

Generated OCI applications stop with the protected-service target when secrets
are locked. Enabled persistent OCI applications and their readiness gates join
that target again on secret activation. A generated OCI owner cannot start
without the runtime secret-ready marker.

Use the Services error and read-only status and journal information to identify
the failed gate. Replace `APP` with the service identifier:

```bash
sudo nas-managed-services-control status
sudo journalctl -b -u nas-v2-ready-APP.service -u nas-managed-services-reconcile.service
```

Check the declared endpoint, path or native-unit probe and the workload's own
logs. Correct the application definition or its dependency, then retry through
Services. An affected unit that is starting, stopping or reloading must settle
before a safe snapshot can be taken. A changed state detected immediately before
mutation also rejects the apply. Keep lifecycle changes on the coordinated
Cockpit/CLI path; avoid direct concurrent `systemctl` changes during an apply.
The final state recheck narrows the race but cannot lock arbitrary root actions. If the error reports manual recovery,
inspect the named units before retrying. Do not clear a readiness failure just
to make an update appear successful; earlier probe failures remain in the
journal even when a later probe succeeds.

## Replication drill cleanup

`./scripts/live-validation.sh syncoid` creates a disposable child dataset under `NAS_SYNCOID_SOURCE` and claims `<NAS_SYNCOID_TARGET>/nas-live-<timestamp>` on the receiving host. A successful drill destroys the source child and its snapshot, the clone, the replicated `@validation` snapshot, the replica, and the claim, all non-recursively. No replicated target dataset remains after a successful drill.

A failed replication or verification is deliberately left in place for inspection: the claim dataset and any replica, complete or partial, beneath it remain on the receiving host. Review the Syncoid error or the failed marker check before destroying them manually; the drill does not retry or clean a failed target.

## Failed identity account-plan recovery

An interrupted `nas-identity-sync apply-accounts` can leave the durable
account-plan journal in `failed` status. A corrected plan with a different
fingerprint is intentionally blocked until the operator reviews the partial
changes: some earlier Authentik user or password operations may already have
succeeded, even when the entire plan failed.

Inspect the password-free journal summary, the live identity model, and every
account the failed plan touched. `nas-identity-sync status` lists usernames
only; it does not show an account's active state, email, or group membership:

```bash
sudo nas-identity-sync account-journal
sudo nas-identity-sync status
sudo nas-identity-sync export-account USERNAME
```

Run `export-account` for each username named in the journal steps and compare
its active state, email, and base identity roles against the intended plan.
The journal and exports never return passwords. If the failed plan included a
password change, verify the account's actual credential in Authentik (Users >
account > set or reset password) before assuming the old or new password is in
effect, and record what you verified in the cancellation note.

Only after reviewing the completed and failed steps, explicitly abandon the
**failed** journal using the exact fingerprint and journal revision reported
above, plus a note:

```bash
sudo nas-identity-sync cancel-failed-accounts \
  --fingerprint FINGERPRINT_FROM_ACCOUNT_JOURNAL \
  --revision REVISION_FROM_ACCOUNT_JOURNAL \
  --note "Reviewed partial account changes and prepared a corrected plan"
```

The revision covers the whole journal state, not just the plan. If another
operator resumes the same plan and it fails after further steps, the previous
revision no longer matches and cancellation is refused until the new state is
inspected.

Cancellation preserves an owner-private verbatim copy of the cancelled journal
under `/var/lib/nas-identity-sync/account-plan-history/`, together with a
separate `-cancellation.json` record holding the fingerprint, journal revision,
timestamp, note, and archive path. The record survives a later corrected
`apply-accounts`, which replaces only the active journal. Cancellation does
**not** undo any Authentik changes, restore passwords, delete identities, or
automatically replay the plan. Running, ambiguous, completed, and
manual-recovery-required journals cannot be cancelled by this command. After
cancellation, preview the corrected plan and apply it deliberately using the
normal workflow.

## Updates

`nas-update` separates review/validation from deployment. It validates the candidate checkout, tests and builds the target generation, records update state, and retains NixOS rollback behavior.

Use `sudo nas-update --status --json` to inspect the source checkout and current
generation link without requiring deployment tools. Status does not build,
activate a generation, or establish appliance health.

Use **Preview and validate updates** before deployment. After applying an update, verify Cockpit, storage, authentication, and protected-service readiness before considering the deployment complete.

Persistent deployment requires an independent management probe. Declare it in
the NixOS configuration as an argument vector whose first element is an absolute
executable path:

```nix
nas.update.externalProbeCommand = [
  "${pkgs.openssh}/bin/ssh" "-o" "BatchMode=yes" "probe@monitor.lan" "check-nas-reachability"
];
```

The command must confirm from outside the NAS that its management path is
reachable; a check that only contacts the NAS from itself is not independent.
The arguments are stored in the Nix store, so let the probe read any credential
from its own private file. The installed `nas-update` takes the probe only from
this option and runs it without a shell after local health checks pass. A failing
probe rolls the update back.

`nas-update --status --json` lists every reason `--apply` would refuse in
`applyBlockers`:

- no probe is configured;
- the configured probe is invalid, including a first element that is not an
  existing executable;
- protected services are stopped;
- a Managed Services reconciliation is pending or running;
- an application that Managed Services expects to run is down.

**Source & updates** shows these reasons and disables Apply, and
`nas.autoUpdate.apply` cannot be enabled without a probe. Validation and fetching
remain available. Status never launches the probe or contacts applications.
`--allow-local-health-only` is a recovery-plane override for an absent probe, not
permission to ignore an invalid one; Cockpit never passes it.

### Health checks after activation

After activating a candidate, `nas-update` checks fixed infrastructure: SSH,
storage, trusted interfaces, PostgreSQL, Authentik, Caddy, Cockpit and the
management route. It also checks every unit that Managed Services V2 last
committed to start. An application turned off in Managed Services is not
required to run. Restarted applications may still be starting, so the check
waits up to five minutes in total, one shared deadline, for Managed Services
reconciliation to settle and for each unit to become active. A unit that fails,
or is still not active at the deadline, fails the check. A readiness gate, which runs once and then stops,
only has to finish without failing.
The same application check runs before building. If an enabled application is
already down, or a Managed Services reconciliation is still pending or running,
`--apply` refuses before any snapshot or activation. Repair the application,
turn it off, or wait for reconciliation to settle first. If the V2 start state is missing or invalid
while protected services run, `--apply` refuses rather than guessing.

## Schedules

Managed Services V2 job schedules compile to native systemd timers. Do not create a parallel timer for the same V2-owned job. The optional Cockpit Scheduler integration remains available for host tasks that are not owned by V2.

Common scheduled work includes:

- Sanoid snapshots;
- ZFS scrub and trim;
- Syncoid replication;
- Restic backup and restore verification;
- SMART tests;
- identity reconciliation and health checks; and
- optional update validation/application.

Check **Maintenance timers** in Cockpit or `systemctl list-timers` when troubleshooting missed work.
