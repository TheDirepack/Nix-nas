# State bundle scope

`nas-state` is the small, versioned migration and validation bundle for mutable control configuration. It is not a second application-data backup system.

The installed registry contains only configuration that is both runtime-editable and useful to move as one small bundle:

- Managed Services desired state (`/var/lib/nas-control/services.yaml`);
- mutable CopyParty administrator configuration;
- NetworkManager connection profiles when NAS networking is enabled;
- Cockpit Scheduler state when that backend is selected.

Application databases, service caches, generated runtime state, secrets databases, VM state, identity databases, observability data, and AI data do not belong in the state bundle. Their recovery owners are the existing native mechanisms:

- Restic for boot/configuration material and configured V2 backup resources;
- native database dumps for consistency-sensitive databases;
- ZFS snapshots/Sanoid/Syncoid for ZFS-backed datasets and replication;
- application-native recovery where a service already owns the format.

This split deliberately removes the need to stop every protected service merely to export `nas-state`. State restore still validates the bundle, creates rollback material, applies the small authority set, and restarts/reconciles the native consumers of restored configuration.

`nas-doctor` remains useful: it reports authority drift and recovery state for the configuration bundle even though bulk application data is restored separately.
