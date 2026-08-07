# Syncthing

The global Syncthing UI at `/syncthing/` is administrator-only. Use it for advanced inspection and settings that belong to Syncthing itself.

Ordinary users manage only their own device declarations through `/settings/syncthing`. Authentik stores those declarations in `attributes.nasSyncthingDevices`; the NAS does not maintain a separate user-settings database.

The reconciler:

- validates device IDs, names, and addresses;
- manages only reserved `nas-*` folders and devices;
- preserves unrelated manually managed Syncthing objects; and
- accepts the legacy singular device attribute only as a migration fallback.

Syncthing remains authoritative for its API key, local device identity, folder database, versioning, and conflict behavior. Include its configuration directory in recovery backups and use upstream folder versioning/`maxConflicts` rather than adding a second NAS conflict engine.
