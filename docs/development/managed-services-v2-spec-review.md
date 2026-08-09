# Managed Services V2 specification redesign

This document records the review passes used to converge the declarative Managed Services V2 application specification. The canonical machine-readable contract is `schemas/managed-services-v3.schema.json`; the product remains **Managed Services V2** while `schemaVersion = 3` denotes the third persisted document shape.

## Goal

Adding or changing an application must be a **data change**, not a controller-code change.

A service definition must be sufficient for the generic V2 engine to understand:

- runtime selection
- enabled state and lifecycle
- dependencies and readiness
- storage and backup classification
- network policy
- CPU/memory/PID limits
- GPU/accelerator and device access
- credentials by reference (never secret values)
- ingress endpoints and authorization
- portal/GUI metadata

Application-specific Python/Nix wake functions, resource handlers, or lifecycle branches are prohibited. Native runtime configuration remains native: Quadlet, Compose and libvirt definitions are referenced rather than reimplemented.

## Review pass 1 — remove duplicated authority

Problems found in the previous schema:

- `runtime.startPolicy` duplicated `lifecycle.mode`.
- `ownership = system|v2|runtime` mixed provenance with lifecycle authority.
- endpoints could contain direct Authentik users/groups even though Authentik is the assignment authority.
- service and endpoint portal metadata overlapped.
- systemd services could only reference pre-existing units, so a genuinely new native executable could still require new Nix code.
- GPU intent was an opaque string list and therefore awkward for a GUI.

Changes:

- canonical lifecycle is only `persistent`, `on-demand`, or `session` plus `enabled`.
- canonical authorization uses capabilities or generic credential references; users/groups are migration-only and not part of v3.
- portal visibility is endpoint-specific; service metadata only describes the application.
- systemd runtime supports either existing units or a generic executable definition.
- accelerator requests are structured objects.

## Review pass 2 — make the schema GUI-native

Problems found:

- mini-languages such as `optional:nvidia:all` force the GUI and users to parse strings.
- app-specific auth modes such as an AI API key would leak application knowledge into the gate.
- dependency ordering alone is insufficient when a dependency becomes active before its API is usable.

Changes:

- accelerators use structured fields (`kind`, `vendor`, `quantity`, `device`, `required`, `mode`, `target`).
- endpoint authorization is one of `public`, `identity`, `secret`, or `upstream`.
- dependencies are objects with `service` and `condition = started|ready`.
- readiness is generic and supports systemd, TCP, HTTP and path probes.
- JSON Schema titles, descriptions, enums and defaults are intended to drive Cockpit forms directly.

## Review pass 3 — keep runtime-native semantics

Problems found:

- Compose applications can contain multiple inner services, so storage/GPU attachment is ambiguous without a target.
- libvirt virtiofs uses a mount tag, not a guest path.
- VM GPU passthrough is fundamentally different from shared host/container GPU access.
- credentials copied into environment variables increase leakage and adapter complexity.

Changes:

- storage and accelerator attachments have optional runtime-local `target`; Compose requires it when the policy applies to one inner service.
- VM storage keeps both `mountPath` (intended guest mount) and `target` (virtiofs tag).
- VM accelerators require explicit PCI passthrough; `auto`/vendor sharing is for host/container runtimes.
- credentials are file references under `/run/nas-secrets` and are mounted/loaded read-only. V2 does not expand secret values into environment variables.

These choices follow native capabilities rather than emulating them. Current Compose supports host device and CDI entries, Podman Quadlet supports device/CDI projection, and libvirt requires explicit host-device/virtiofs semantics.

## Review pass 4 — session leases and dependency correctness

Problem found:

An enabled session service does not imply that a session is active. Treating all enabled session services as active can keep their on-demand dependencies alive forever.

Change:

V2 owns generic **session leases**:

- `session begin <service>` creates an instance lease and starts/touches dependencies.
- `session touch <service> <instance>` refreshes the lease and dependency usage.
- `session end <service> <instance>` removes the lease.
- the reaper considers only live leases when deciding whether an on-demand dependency is still needed.

The session executor/launcher may be Pi, a shell, a future coding agent, or another runtime; dependency code never branches on application identity.

## Review pass 5 — minimize implementation code

Problem found:

Incremental development produced layered wrappers around the legacy engine. The behavior is generic, but the composition itself is more complex than necessary.

Final implementation boundary:

1. **JSON Schema** — structural validation and GUI contract.
2. **Spec normalizer** — defaults plus semantic cross-reference validation; no application names.
3. **Generic engine** — dependency graph, readiness, lifecycle, session leases, authorization wake/touch integration.
4. **Resource resolvers** — storage/network/accelerator/credential resolution from host state.
5. **Thin runtime adapters** — systemd, Quadlet, Compose, libvirt. They project already-resolved generic policy into native configuration.
6. **Projection adapters** — Caddy, CopyParty, Authentik, Restic consume the same normalized effective spec.

There must be no application-specific conditional in layers 2–6.

## Final canonical concepts

### Top-level document

- `schemaVersion`
- `generation`
- `storageResources`
- `networkProfiles`
- `credentials`
- `services`

### Service

- `name`, `description`
- `enabled`
- lifecycle authority (`managed` in schema v3; V2-managed vs core substrate)
- `runtime`
- `lifecycle`
- `dependencies`
- `readiness`
- `resources`
- `storage`
- `credentials`
- `networkProfile` / `network`
- `endpoints`

### Runtime choices

- existing systemd units
- generic systemd executable
- native Quadlet source
- native Compose source
- native libvirt XML

A new runtime *kind* may require one new generic adapter. A new application using an existing runtime never should.

### Lifecycle

- `persistent`: V2 keeps the runtime available while enabled.
- `on-demand`: V2 starts it when an authorized consumer uses it and reaps it after idle time.
- `session`: the runtime exists only for active session lease(s); persistent storage is independent of runtime lifetime.

### Dependencies

Dependencies may cross runtime boundaries. A systemd service can depend on Compose, a VM can depend on Quadlet, etc. V2 operates on service IDs and delegates execution to each service's runtime adapter.

### Hardware

Hardware intent is service data. A model runner can request an optional GPU; a future Starlight server can use the same request. The engine resolves hardware without knowing either application name.

### Authority rule

If adding an application requires editing Python controller code, the spec or a generic runtime/resource adapter is incomplete. The application must instead be expressible by changing only declarative V2 data and native runtime source where that runtime inherently has its own configuration format.

## Remaining implementation migration

- make schema v3 the canonical validation input and implement deterministic defaults
- replace wrapper stack with one normalizer/engine
- add generic readiness and session leases to that engine
- make secret endpoint authorization generic
- re-express every built-in application with the canonical v3 fields
- remove old feature-mode lifecycle authority
- remove v2 compatibility fields once the built-in migration and store migration are complete
- generate Cockpit forms/status from the schema and effective document rather than maintaining separate feature settings
