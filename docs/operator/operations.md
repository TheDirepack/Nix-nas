# Operator command index

The installed manual under `docs/src/` is the canonical task guide. This page is a source-tree command index for console recovery and maintenance.

## Start with diagnostics

```bash
nas-doctor
nas-doctor --json
systemctl --failed
```

`nas-doctor` combines setup state, Managed Services V2 desired/effective-state validation, state-authority health, and active privileged-operation status. Human output includes the next recovery action when one is known; use `--json` for automation.

## First installation

- [Install and set up](../src/admin/installation.md)
- [Administrator configuration](../src/admin/configuration.md)
- [First start](../src/admin/first-run.md)
- [Storage installation and recovery](../src/admin/storage-recovery.md)

```bash
nas-setup validate-config /path/to/first-run.json
nas-setup prepare-first-start --config /path/to/first-run.json
nas-setup status
```

Complete the workflow itself through the browser First start wizard; it confirms the plan digest and every storage device and runs the guarded job. New-pool creation additionally requires the wizard's destructive opt-in and one exact confirmed device per configured disk.

## Locked boot and secrets

- [Locked-state unlock](../src/locked-unlock.md)
- [Recovery runbook](recovery.md)

Use the local console, SSH with a provisioned recovery key, or hardware KVM. Locked boot has no browser recovery path.

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

Authentik owns human identities, groups, and capability assignments. Managed Services V2 only ensures the `application.<service>.<capability>` objects referenced by `services.yaml`.

## Managed Services V2 policy

`/var/lib/nas-control/services.yaml` is the only mutable application desired-state authority. Use the finite V2 operator commands; there is no resident feature controller or feature database.

```bash
nas-managed-services-control status
nas-managed-services-control document
nas-managed-services-control set grafana always
nas-managed-services-control set ai-runtime on-demand
nas-managed-services-control reconcile
systemctl status nas-managed-services-reconcile.service
```

For larger edits, retrieve the current YAML/schema with `document`, edit the YAML, then atomically validate/replace it:

```bash
nas-managed-services-control replace-document /path/to/services.yaml
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
