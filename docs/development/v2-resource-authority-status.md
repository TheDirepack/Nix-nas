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
- CopyParty administrator receives filesystem-root recovery access; normal system/instance resource ACLs are backed by deterministic Authentik capability groups;
- user-scoped CopyParty resources fail closed: the parent directory is never exposed by the generic projection, and an identity-bound realization is required before mounting a `{user}` path;
- Authentik V2 capability groups are reconciled only while the protected identity plane is active; membership remains managed exclusively in Authentik;
- managed endpoint authorization now prefers Authentik capability groups, with embedded users/groups retained only as migration fallback;
- `cockpit-files` removed; CopyParty remains the sole general-purpose file browser;
- Podman V2 storage is projected using native Quadlet drop-ins and application-directory installation rather than re-rendering Quadlet;
- libvirt adapter now applies native XML and VM removal no longer deletes persistent disks implicitly;
- Compose/libvirt reject attempts to start an unsupported `session` lifecycle, while cleanup/stopping of stale instances remains allowed;
- executable/module contract inventory and installed adversarial fuzz accounting extended for the new V2 commands;
- unsafe mount delimiters/control characters are rejected before runtime projection;
- application availability and lifetime are separate: `enabled` controls whether an app may run, while lifecycle is only `persistent`, `on-demand`, or `session`;
- legacy `runtime.startPolicy` is migration input only (`boot`→persistent, `on-demand`→on-demand, `manual`→session, `disabled` requires `enabled=false`);
- persistent V2 apps are enforced running at reconcile; disabled apps are stopped; session apps are prevented from becoming boot-persistent;
- on-demand access starts/touches the native runtime through the existing authorization gate, and a systemd timer invokes a short-lived reaper after `idleSeconds` with no new resident lifecycle daemon;
- static endpoint access never auto-creates a session-scoped application;
- built-in service metadata now uses the same V2 lifecycle labels: core identity/sync/vault/metrics services are persistent while llama-swap/Open WebUI/model downloader/Grafana/UPS UI are marked on-demand;
- Pi coding sessions now run with `podman run --rm` using a reproducible Nix-built OCI image, read-only container root, all capabilities dropped, no-new-privileges, bounded CPU/RAM/PIDs/runtime, a read-only llama-swap credential mount, and the existing restricted network namespace;
- Pi state is scoped to `/tank/.../apps/pi/users/<authenticated-user>` while the chosen workspace remains a separate mount, so the session runtime can disappear without losing authoritative user state;
- Pi itself is no longer exposed as the host execution path; the supported path is the authenticated launcher plus the session image;
- code version advanced to `2.2.0-alpha.8`.

## In progress

- migrate remaining built-in service definitions from embedded endpoint groups/users to V2 capability references;
- finish generic identity-bound user-scoped resource realization for consumers that support safe per-user templates;
- move Pi networking from the temporary legacy netns/proxy to a native Podman + firewalld V2 network profile after the container-session path is validated;
- add explicit runtime-target mapping needed for multi-service Compose storage and VM sharing;
- replace the custom state bundle with ZFS snapshots + Restic + native database dump/restore and benchmark Backrest idle RSS;
- replace complex operation reservations with small FD-based locks and systemd lifetime;
- continue Caddy, firewalld, Syncthing and libvirt upstream-native simplification;
- synchronize every release/version surface and rebuild generated Cockpit artifacts before the PR is ready;
- run the full local/VM validation matrix once a repository execution environment is available.

## Migration rule

Do not keep parallel authorities indefinitely. Compatibility exists only to migrate old V2 documents and then is removed once all built-ins/tests use the new model.
