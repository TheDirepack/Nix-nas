# Maintenance, service policy, and updates

Use the NAS Cockpit page for routine maintenance. It exposes only fixed, reviewed backend operations; it is not a general root shell.

## Service policy

Optional features can expose one or more runtime modes:

- **Off** — keep the feature stopped.
- **On demand** — start it for authorized use and stop it after the configured idle period.
- **Always on** — keep it resident.

The feature controller handles dependencies, readiness, and safe idle shutdown. NixOS still decides which features are installed. VictoriaMetrics remains resident for continuous history; Grafana can sleep independently.

## Maintenance actions

Depending on installed features, Cockpit can run health checks, identity validation, snapshots, ZFS scrub, backup, replication, Syncthing reconciliation, protected-stack restart, and update workflows.

For direct diagnosis, use the generated command reference and systemd journal rather than bypassing the fixed action boundary.

## Updates

`nas-update` separates review/validation from deployment. It validates the candidate checkout, tests and builds the target generation, records update state, and retains NixOS rollback behavior.

Use **Preview and validate updates** before deployment. After applying an update, verify Cockpit, storage, authentication, and protected-service readiness before considering the deployment complete.

## Schedules

Use one scheduling authority for each job. The appliance supports native systemd timers and the selected Cockpit Scheduler integration.

Common scheduled work includes:

- Sanoid snapshots;
- ZFS scrub and trim;
- Syncoid replication;
- Restic backup and restore verification;
- SMART tests;
- identity reconciliation and health checks; and
- optional update validation/application.

Check **Maintenance timers** in Cockpit or `systemctl list-timers` when troubleshooting missed work.
