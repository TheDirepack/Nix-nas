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

Persistent deployment requires an independent management probe configured through
`NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON`, a nonempty JSON array of nonempty command
arguments. The updater must finish decoding successfully before running that
command; invalid arguments or decoder failures cannot run a partial command.
Probe failures stop deployment. `--allow-local-health-only` is an explicit recovery
override for an absent probe, not permission to ignore an invalid configured probe.

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
