# V2 resource-authority branch status

This is a live implementation branch stacked on PR #25.

## Implemented

- authority boundary documented: V2 owns resources/application intent, Authentik owns assignments, CopyParty owns human file browsing, native runtimes own execution;
- shared storage-resource schema and executable validation introduced;
- stable application principals and Authentik capability references introduced;
- state classes and backup inventory derivation implemented;
- live managed-service schema accepts named storage resources, network profiles and capability-backed endpoints while legacy shapes remain migration input;
- `nas-managed-service` now runs through a V2 compatibility layer which resolves named storage references and preserves the previous hardened validator;
- effective registry now carries `storageResources`, `backupResources`, `networkProfiles`, stable principals and `resolvedStorage`;
- CopyParty storage projection implemented and wired into the existing path-triggered reconcile oneshot;
- CopyParty administrator receives filesystem-root recovery access; normal resource ACLs are backed by deterministic Authentik capability groups;
- Authentik V2 capability groups are reconciled only while the protected identity plane is active; membership remains managed exclusively in Authentik;
- managed endpoint authorization now prefers Authentik capability groups, with embedded users/groups retained only as migration fallback;
- `cockpit-files` removed; CopyParty remains the sole general-purpose file browser;
- Podman V2 storage is projected using native Quadlet drop-ins and application-directory installation rather than re-rendering Quadlet;
- libvirt adapter now applies native XML and VM removal no longer deletes persistent disks implicitly;
- executable/module contract inventory and installed adversarial fuzz accounting extended for the new V2 commands;
- unsafe mount delimiters/control characters are rejected before runtime projection;
- code version advanced to `2.2.0-alpha.8`.

## In progress

- migrate built-in service definitions from inline mounts and embedded endpoint groups/users to V2 resource/capability references;
- add the explicit runtime-target model needed to project V2 resources safely into multi-service Compose applications and VM sharing;
- implement user-scoped resource realization without exposing parent directories;
- convert Pi to an ordinary on-demand Podman-backed V2 application with persistent per-user authoritative state;
- replace the custom state bundle with ZFS snapshots + Restic + native database dump/restore and benchmark Backrest idle RSS;
- replace complex operation reservations with small FD-based locks and systemd lifetime;
- continue Caddy, firewalld, Syncthing and libvirt upstream-native simplification;
- synchronize every release/version surface and rebuild generated Cockpit artifacts before the PR is ready;
- run the full local/VM validation matrix once a repository execution environment is available.

## Migration rule

Do not keep parallel authorities indefinitely. Compatibility exists only to migrate old V2 documents and then is removed once all built-ins/tests use the new model.
