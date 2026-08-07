# Operator command index

The installed manual under `docs/src/` is the canonical task guide. This page is a source-tree command index for console recovery and maintenance.

## Start with diagnostics

```bash
nas-doctor
nas-doctor --json
systemctl --failed
```

`nas-doctor` combines setup state, feature policy, state-authority health, migrations, and active privileged-operation status. Human output includes the next recovery action when one is known; use `--json` for automation.

## First installation

- [Administrator configuration](../src/admin/configuration.md)
- [First start](../src/admin/first-run.md)
- [Storage installation and recovery](../src/admin/storage-recovery.md)

```bash
nas-setup validate-config /path/to/first-run.json
nas-setup prepare-first-start --config /path/to/first-run.json
nas-setup first-run --config /path/to/first-run.json --confirm-plan-digest <digest>
nas-setup status
```

New-pool creation additionally requires `--allow-destructive-storage` and one exact `--confirm-storage-device` for every configured disk.

## Locked boot and secrets

- [Locked-state unlock](../src/locked-unlock.md)
- [Recovery runbook](recovery.md)

Cockpit remains available on the trusted LAN at `https://<host>.local:9092/console/`.

```bash
sudo nas-secrets activate
sudo nas-secrets stop
```

## Accounts and access

- [Accounts and access](../src/admin/accounts.md)
- [Permission model](../src/permissions.md)
- [Trusted superusers](../src/admin/superusers.md)

```bash
nas-setup account apply --username alice --password-stdin
nas-setup account disable alice
nas-identity-sync status
nas-identity-sync sync
```

## Feature and service policy

```bash
nas-feature-control status
nas-feature-control set grafana always
nas-feature-control set aiRuntime on-demand
systemctl status nas-protected-services.target
```

See [Configuration and management map](../src/admin/service-map.md) before changing mutable application settings from the command line.

## Storage and backup

- [Maintenance and service policy](../src/admin/maintenance.md)
- [Observability and alerts](../src/admin/observability.md)
- [Snapshots, replication, and backups](../src/admin/backups.md)

For direct diagnosis:

```bash
zpool status
zfs list
systemctl list-timers
journalctl -b
```

State-bundle operations:

```bash
sudo nas-state export --output /path/to/nas-state.tar.gz --include-sensitive
sudo nas-state validate /path/to/nas-state.tar.gz
sudo nas-state diff /path/to/nas-state.tar.gz
sudo nas-state restore /path/to/nas-state.tar.gz --confirm-host "$(hostname)" --include-sensitive
```

The scheduled restore verifier is as important as the backup job itself; inspect its result before relying on a backup for recovery.

## Deployment and validation

```bash
nas-update --status --json
./scripts/preflight.sh
nix develop .#qemu-test -c ./scripts/qemu-test.sh all
```

The full QEMU/installer matrix, environment overrides, and failure artifacts are documented in [QEMU and installer validation](../development/vm-testing.md).
