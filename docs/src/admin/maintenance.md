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

## Updates

`nas-update` separates review/validation from deployment. It validates the candidate checkout, tests and builds the target generation, records update state, and retains NixOS rollback behavior.

Use **Preview and validate updates** before deployment. After applying an update, verify Cockpit, storage, authentication, and protected-service readiness before considering the deployment complete.

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
