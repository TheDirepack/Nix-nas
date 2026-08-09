# Managed Services V2 specification redesign

This document records the review passes used to converge the declarative Managed Services V2 application specification. The canonical machine-readable contract is `schemas/managed-services-v3.schema.json`; the product remains **Managed Services V2** while `schemaVersion = 3` denotes the third persisted document shape.

## Goal

Adding or changing an application must be a **data change**, not a controller-code change.

A service definition must be sufficient for the generic V2 engine to understand runtime selection, workload/lifecycle, dependencies/readiness, storage/backup classification, network policy, resources/devices, credentials, ingress/auth, scheduling, and portal/UI metadata.

Application-specific Python/Nix wake functions, resource handlers, or lifecycle branches are prohibited. Native application configuration remains native and may be referenced as an artifact rather than reimplemented by V2.

## Review pass 1 — remove duplicated authority

Problems found in the previous schema:

- `runtime.startPolicy` duplicated `lifecycle.mode`.
- `ownership = system|v2|runtime` mixed provenance with lifecycle authority.
- endpoints could contain direct Authentik users/groups even though Authentik is the assignment authority.
- service and endpoint portal metadata overlapped.
- systemd services could only reference pre-existing units, so a genuinely new native executable could still require new Nix code.
- GPU intent was an opaque string list and therefore awkward for a GUI.

Changes:

- remove canonical `startPolicy`;
- canonical authorization uses capabilities or generic credential references;
- portal visibility is endpoint-specific;
- systemd runtime can reference existing units or a generic executable;
- accelerator requests are structured objects.

## Review pass 2 — make the schema GUI-native

Problems found:

- mini-languages such as `optional:nvidia:all` force the GUI to parse strings;
- app-specific auth modes leak application knowledge into the gate;
- dependency ordering alone is insufficient when a dependency becomes active before its API is usable.

Changes:

- accelerators use structured fields;
- endpoint authorization is one of `public`, `identity`, `secret`, or `upstream`;
- dependencies are structured objects;
- readiness is generic and supports systemd, TCP, HTTP and path probes;
- JSON Schema titles/descriptions/enums/defaults are intended to drive Cockpit forms directly.

## Review pass 3 — keep runtime-native semantics

Problems found:

- Compose applications can contain multiple inner services;
- libvirt virtiofs uses a mount tag, not a guest path;
- VM GPU passthrough is fundamentally different from shared host/container GPU access;
- credentials copied into environment variables increase leakage and adapter complexity.

Changes:

- storage and accelerator attachments can carry a runtime-local target;
- VM storage keeps an intended guest mount plus a virtiofs target tag;
- VM accelerators require explicit PCI passthrough;
- credentials are file references under `/run/nas-secrets`; secret values are never persisted in the spec.

## Review pass 4 — session leases and dependency correctness

Problem found:

An enabled session-capable service does not imply an active session. Treating it as active can keep on-demand dependencies alive forever.

Change:

V2 owns generic session leases:

- begin creates an instance lease and satisfies dependencies;
- touch refreshes the lease and dependency use;
- end removes it;
- the reaper considers only live leases.

No session lease code knows the application name.

## Review pass 5 — minimize implementation code

Incremental development produced too many wrappers. The final boundary is:

1. JSON Schema — structure and GUI contract.
2. YAML loader + spec normalizer — strict YAML 1.2 parsing, deterministic defaults, semantic references.
3. One generic engine — dependency graph, readiness, daemon/job/session activation, leases, reconciliation and reaping.
4. Resource resolvers — storage/network/accelerator/credentials/host capabilities.
5. Thin runtime adapters — systemd/executable, Quadlet, Compose, libvirt, and a minimal Podman session runtime if required.
6. Generic projections — Caddy, CopyParty, Authentik and Restic consume the same effective spec.

There must be no application-specific condition in layers 2–6.

## Review pass 6 — derive the contract from every existing workload

The full audit is in `managed-services-v2-workload-matrix.md`. It found that the previous lifecycle model was still daemon-centric.

Existing one-shot work includes Authentik migration, AI storage/config preparation, Vaultwarden CA export, identity reconciliation, Syncthing reconciliation, backup, restore verification, Syncoid and automatic update. Those are jobs, not persistent services.

Change: separate **workload kind** from daemon activation.

- `daemon`: long-running; activation is `persistent` or `on-demand`.
- `job`: finite; may be invoked manually, as a dependency, or by a schedule.
- `session`: exists only for live session lease(s).

Dependency conditions become:

- `started` — runtime activation returned successfully;
- `ready` — declared readiness probes succeeded;
- `completed` — a job completed successfully.

This allows a daemon to depend on a completed migration/preparation job without inventing hooks.

## Review pass 7 — do not add hook or templating mini-languages

A generic `preStart/postStart/preBackup/...` hook system looks flexible but duplicates the dependency graph and becomes hard to display or reason about in a GUI.

Decision: **no lifecycle hooks**. Preparation/migration/verification is modeled as ordinary job services.

Likewise V2 will not invent a template language for arbitrary application configuration. Native config is a referenced artifact owned by the application. V2 may later gain a small generic managed-file primitive if the workload matrix proves it necessary, but application-aware renderers are prohibited.

## Review pass 8 — separate application intent from host/platform capabilities

Some current workloads need host privileges or substrates that cannot safely be synthesized from app data:

- ZFS mounted/unlocked state;
- Podman/libvirt;
- GPU kernel drivers/CDI inventory;
- network-online;
- the tightly restricted SMART helper used by Telegraf;
- minimal Authentik/Caddy/control-plane services needed for V2 itself.

Decision: NixOS publishes a **named host-capability inventory**. Services may reference capabilities. Adding an application that uses existing capabilities remains data-only. Adding a genuinely new privileged/kernel/platform capability is a platform change and must be designed generically.

Core services may appear in the service graph as externally lifecycle-owned nodes so V2 can ensure/readiness-check dependencies without claiming their shutdown/reaping authority.

## Review pass 9 — choose YAML for desired state, JSON Schema for contract

The persisted human/admin desired-state format is YAML 1.2. The structural/UI contract remains JSON Schema 2020-12.

Reasons:

- comments and readable diffs matter for appliance administration;
- deeply nested service definitions are more usable in YAML than JSON;
- JSON is valid YAML 1.2 input, preserving import compatibility;
- JSON Schema remains the mature machine validation and GUI-form contract.

Pipeline:

1. strict YAML 1.2 parse; duplicate keys are errors;
2. JSON Schema validation;
3. one deterministic defaulting/normalization pass;
4. semantic validation of cross-references/cycles/runtime-specific constraints;
5. host-resource/capability resolution;
6. native runtime/projection application.

The GUI and hand-written YAML therefore reach exactly the same normalized document.

## Review pass 10 — remove Nix as a second application settings database

Current built-ins interpolate Nix options for enable flags, ports, paths, retention, memory profiles and other application settings. Keeping that indefinitely would leave two writable configuration authorities.

Target:

- Nix defines platform defaults, packages, kernel/runtime substrate and host capabilities;
- first-run/migration converts current Nix application settings into V2 desired state;
- Cockpit edits V2 desired state through the schema;
- application settings are no longer duplicated as mutable Nix options once migration is complete.

No YAML interpolation language is introduced. The persisted document contains resolved values.

## Review pass 11 — ingress must model the real current routes

The existing Caddy configuration proves a simple `path -> port` endpoint is insufficient. The final generic endpoint model must represent without raw snippets:

- path-prefix stripping;
- static and trusted identity-derived request headers;
- response header set/remove;
- WebSockets;
- Unix socket targets;
- multiple routes to one runtime with different auth;
- header/referrer/origin match constraints for applications that emit absolute asset/API routes;
- public, identity-capability, secret/API credential and upstream-native authorization;
- HTTP hostname/path and raw TCP/UDP port/range exposure;
- optional mDNS discovery metadata.

If any existing route still needs an application-specific Caddy branch after migration, the endpoint spec is incomplete.

## Review pass 12 — session inputs must be generic enough to remove Pi-specific launch code

Pi currently needs an authenticated identity, per-user state, and a caller-selected workspace constrained under approved roots. A generic session engine cannot remove the custom launcher unless it can safely represent this interaction.

Decision: session workloads may declare **path inputs**. Each input references an authorized storage resource, optionally allows selection of a descendant subpath, declares read/write access, and binds the resolved path to a runtime mount destination. Resolution uses the authenticated identity and rejects symlink/path escape.

This primitive is reusable for shells, coding agents, media-processing sessions and future tools. It is not called `workspace` in the engine.

## Final canonical concepts

### Top-level desired-state document

- `schemaVersion`
- `generation`
- `storageResources`
- `networkProfiles`
- `credentials`
- `services`

Host capabilities are supplied by a separate immutable platform inventory generated by NixOS; services reference them by ID.

### Service

- name/description
- enabled
- lifecycle ownership (`managed` boolean)
- workload kind/activation
- runtime
- dependencies
- readiness
- required host capabilities
- resource limits + accelerators
- sandbox policy
- storage attachments
- credential attachments
- network policy/profile
- endpoints
- session inputs when workload kind is `session`

### Runtime choices

- existing systemd units
- generic executable through systemd
- native Quadlet
- native Compose
- native libvirt XML
- minimal generic OCI session execution when dynamic per-session mounts/identity are required

A new runtime *kind* may require one generic adapter. A new application using an existing runtime never should.

### Authority rule

If adding an application requires editing Python controller code, Caddy application branches, Cockpit application forms, or Nix lifecycle code, either the spec is incomplete or a genuinely new generic host/runtime capability has been discovered. The generic primitive must be designed first; application names do not belong in the engine.

## Remaining implementation migration

- revise schema v3 around daemon/job/session workload kinds, host capabilities, complete endpoint transforms and session path inputs;
- add strict YAML 1.2 + JSON Schema loader and deterministic normalizer;
- collapse the wrapper stack into one generic engine;
- implement readiness and session leases in that engine;
- add generic systemd executable/job and generic scheduled-job projection;
- make secret endpoint authorization generic;
- re-express every built-in application with the canonical YAML fields;
- migrate current Nix application settings into V2 desired state and deprecate duplicate options;
- remove old feature-mode lifecycle authority;
- remove compatibility fields and application-specific route/wake branches;
- generate Cockpit forms/status from schema + effective document rather than maintaining separate feature settings.
