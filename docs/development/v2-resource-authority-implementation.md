# Managed Services V2 resource-authority implementation

This branch is intentionally stacked on PR #25 (`fix/ci-runtime-and-code-fixes-20260808`) and must be rebased onto that branch until PR #25 lands.

## Authority boundaries

The implementation target is deliberately narrow:

- Managed Services V2 owns application/runtime intent and resource definitions.
- Authentik owns human users, groups, application/service identities, capabilities, and authorization assignments.
- CopyParty is the sole general-purpose human filesystem browser and file-transfer surface.
- Podman/Quadlet, Compose, libvirt, systemd, Caddy, firewalld, Syncthing, Restic, ZFS, and native database tooling remain authoritative in their own domains.
- Cockpit is limited to appliance-specific orchestration plus mature upstream Cockpit modules. It must not duplicate file browsing, identity administration, capability assignment, or a backup UI when an adequate upstream UI is selected.

## V2 resource model

V2 evolves from per-service host-path mounts into named storage resources. A storage resource describes the durable thing once; applications reference it.

```yaml
storageResources:
  projects:
    path: /tank/projects
    dataset: tank/projects
    stateClass: authoritative
    capabilities: [read, write, move, delete]
    backup:
      enabled: true
      consistency: filesystem
```

Services retain runtime-specific mount destinations but do not become the authorization database:

```yaml
services:
  pi:
    principal: application:pi
    storage:
      - resource: projects
        guestPath: /workspace
```

During migration, the existing inline `hostPath` storage form remains readable. New writes should prefer resource references once the runtime adapters understand them.

## Authorization model

V2 resources expose stable capability identifiers; Authentik owns assignments. For example:

- `application.pi.access`
- `storage.projects.read`
- `storage.projects.write`
- `storage.projects.move`
- `storage.projects.delete`

Endpoint policy therefore converges from embedded user/group lists toward a stable capability reference. Existing group/user fields remain migration input only until all consumers have moved.

Every managed application receives a stable principal (`application:<service-id>`) independent of its runtime. Changing an application from Podman to libvirt must not invalidate storage or access policy.

## State classes

All V2 storage resources are classified as one of:

- `authoritative`: must survive rebuilds and should normally be backed up;
- `derived`: reconstructable state, backup optional;
- `cache`: regenerable cache, normally excluded from backup;
- `ephemeral`: expected to disappear with the runtime.

Backup selection is derived from this model rather than maintained as a second path registry.

## Projection pipeline

The existing file-backed, systemd-path-triggered, oneshot reconciliation model is retained. It should evolve into deterministic projections rather than a resident control-plane daemon:

```text
V2 resource definitions + Authentik authorization
                 |
                 v
             reconcile
        /        |        \
   CopyParty   runtime    portal/Caddy
      ACLs      mounts       access
                 |
             firewalld
```

Generated projections are not authoritative backup state.

## UI ownership

The NixOS NAS Cockpit plugin should eventually expose all V2 application/resource semantics that belong to the NAS appliance, but it must not duplicate upstream administration surfaces:

- files -> CopyParty;
- users/groups/MFA/capability assignments -> Authentik;
- containers -> Cockpit Podman;
- VMs -> Cockpit Machines;
- ZFS -> Cockpit ZFS;
- metrics -> VictoriaMetrics VMUI;
- backups -> Backrest if its measured idle RSS is acceptable, otherwise Restic plus a lower-idle scheduler/UI arrangement.

`cockpit-files` is explicitly out of scope and should be removed from the appliance package set and navigation.

## Implementation sequence

1. Extend the persisted V2 schema with named resources, stable application principals, state classes, capability references, network profiles, and backup metadata while preserving old documents as migration input.
2. Add central validation/migration and make runtime projections consume resource references.
3. Project storage authorization from Authentik into CopyParty/runtime enforcement.
4. Remove direct identity/capability editing and Cockpit Files.
5. Convert Pi to an ordinary on-demand Podman-backed V2 application with per-user authoritative state and disposable runtime state.
6. Replace the custom state bundle with ZFS snapshots + Restic + native database dump/restore; benchmark Backrest before making it resident.
7. Replace complex operation reservations with small FD-based `flock` locks and systemd unit lifetime.
8. Continue upstream-native simplifications for Caddy, firewalld, Syncthing, and libvirt.
9. Audit always-running processes and convert suitable components to socket/path/timer/oneshot activation.

## Migration rule

Do not keep parallel authorities indefinitely. Compatibility exists only to migrate old V2 documents and then is removed once all built-ins/tests use the new model.
