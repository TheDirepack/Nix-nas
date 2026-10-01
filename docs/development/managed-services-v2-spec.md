# Managed Services V2 consolidated specification

Status: architecture/specification authority for the V2 implementation.

This document supersedes the earlier wrapper-first, feature-controller, object-capability, and identity-aware-session variants of Managed Services V2. It incorporates the workload audit, implementation feedback, and all later boundary corrections.

## 1. Purpose

Managed Services V2 is the generic, GUI-first application definition and provisioning layer for NixOS NAS.

Its job is to let an administrator describe an application once and have the system configure the existing native subsystems required to run it:

- systemd;
- Podman/Quadlet;
- Podman Compose;
- direct OCI containers/sessions where dynamic runtime input makes static Quadlet unsuitable;
- libvirt/QEMU;
- per-service isolated Python virtual environments;
- Caddy;
- Authentik capability objects;
- firewalld;
- CopyParty storage projection where appropriate;
- Restic/ZFS backup inventory;
- native systemd timers/jobs;
- GPU/device access;
- resource limits and sandboxing.

V2 is primarily a **configuration compiler and provisioner**. It is not intended to become a permanent application supervisor, authentication service, authorization database, routing daemon, scheduler daemon, backup daemon, storage daemon, or general-purpose orchestration control plane.

The design goal is:

> If a new application uses runtime and platform primitives V2 already supports, adding it must require only a V2 definition plus the application's own native configuration/artifact. It must not require a new application-specific Python branch, NixOS lifecycle module, Caddy branch, Cockpit form, authorization implementation, backup implementation, or service controller.

A future application must be able to use the same primitives as Grafana, VictoriaMetrics, Vaultwarden, CopyParty, Syncthing, or any user-added service.

## 2. Primary design rules

### 2.1 GUI first

Cockpit is the primary editing surface for V2.

The stored V2 document exists as a durable, inspectable backing format and for import/export/recovery, but administrators should normally configure services through the GUI.

The GUI must be generated from the same schema that validates the stored document. There must not be a second hand-maintained application settings model in Cockpit.

### 2.2 Applications are data

Application names must not appear in generic lifecycle, routing, dependency, device, network, backup, authorization-projection, or GUI code.

Bad:

```python
if service_id == "grafana":
    ...
```

Good:

```yaml
resources:
  accelerators:
    - kind: gpu
      required: false
      vendor: any
```

The only acceptable reason to add generic implementation code for a new application is that the application exposes a genuinely new reusable runtime or platform capability that other applications may also need.

### 2.3 Use native systems instead of replacing them

V2 compiles desired state into the systems that already own those concerns:

| Concern | Authority |
|---|---|
| Users, groups, MFA, assignments | Authentik |
| HTTP authentication and request authorization | Caddy + Authentik |
| Per-user visible service routing/portal filtering | Caddy using Authentik results |
| Service process lifetime | systemd / Podman / Compose / libvirt / application runtime |
| Timers | systemd timers |
| Container networking | Podman/Netavark + firewalld |
| Host firewall | firewalld |
| VM execution | libvirt/QEMU |
| File browser and file-transfer ACLs | CopyParty |
| Backup repository and retention | Restic |
| ZFS snapshots/replication | ZFS/Sanoid/Syncoid/native tools |
| App-native settings | The application/native config format |
| V2 desired-state editing | Cockpit + V2 schema |

V2 should generate or reconcile configuration for these systems, then get out of the way.

### 2.4 No resident V2 controller daemon

There must be no permanently running V2 controller simply to keep applications configured.

V2 should normally run when:

- the GUI saves desired state;
- installation/upgrade seeds or migrates desired state;
- an administrator explicitly applies/validates a definition;
- a systemd path unit notices the authority file changed;
- a native timer invokes a generated V2 job;
- an already-authorized Caddy route needs a minimal socket-activated wake action for an on-demand service.

That wake action is plumbing, not an authorization or policy engine.

Once configuration has been materialized, normal service operation belongs to native subsystems.

## 3. Authority files

### 3.1 Desired state

Canonical mutable authority:

```text
/var/lib/nas-control/services.yaml
```

Authoring format: YAML 1.2.

Why YAML:

- practical for human inspection;
- comments survive;
- clean diffs;
- easy import/export;
- JSON is still valid input-compatible data;
- no need to invent a custom DSL.

### 3.2 Structural and GUI contract

Canonical structural contract:

```text
/etc/nas-control/managed-services-v3.schema.json
```

Format: JSON Schema 2020-12.

The JSON Schema is used for:

- field types;
- enums;
- required fields;
- conditional fields;
- limits/ranges;
- titles and descriptions;
- GUI form generation;
- schema-aware import validation;
- editor autocomplete/documentation.

JSON Schema defaults are annotations only. A deterministic normalizer must apply actual defaults.

### 3.3 Platform capability inventory

NixOS publishes immutable platform facts/capabilities, for example:

```text
/etc/nas-control/platform-capabilities.json
```

This describes capabilities supplied by the host rather than application desired state.

Examples:

- `network-online`;
- `zfs-mounted`;
- `podman`;
- `libvirt`;
- `kvm`;
- `smart-readonly`;
- GPU drivers/runtime support;
- other narrowly defined privileged helper capabilities.

An application may require these capabilities but does not configure the kernel, driver stack, host packages, or privileged helper itself.

### 3.4 Effective state

Compiled runtime view:

```text
/run/nas-control/effective.json
```

or the compatible current effective path during migration.

This is derived state, not authority. It may contain:

- normalized defaults;
- resolved storage paths;
- resolved GPU/device selectors;
- native unit/container/domain names;
- compiled route metadata;
- backup resource inventory;
- generated file locations.

It must never be treated as the user's source of truth.

## 4. Processing model

The canonical apply pipeline is:

1. Parse YAML 1.2 strictly.
2. Reject duplicate mapping keys.
3. Validate against JSON Schema 2020-12.
4. Apply deterministic defaults.
5. Perform semantic validation.
6. Resolve host/platform resources.
7. Build one normalized effective document.
8. Produce plans for native subsystems.
9. Validate generated native configuration where possible.
10. Apply configuration transactionally.
11. Reload/reconcile only the native systems whose generated configuration changed.
12. Exit.

There is no continuous V2 reconciliation loop.

### 4.1 Semantic validation

The semantic validation phase handles only configuration correctness, for example:

- references to missing services/resources/credentials/network profiles;
- dependency cycles;
- impossible dependency conditions;
- invalid runtime-target references;
- unsafe filesystem paths;
- invalid GPU/runtime combinations;
- Compose target ambiguity;
- VM passthrough without an explicit PCI device;
- duplicate Caddy route paths/hostnames;
- duplicate direct listener exposure;
- conflicting storage mount targets;
- unavailable declared host capabilities.

It must **not** validate users, group membership, MFA state, login sessions, or whether a subject is authorized.

## 5. Authentication and authorization boundary

This is a hard architecture boundary.

### 5.1 Authentik owns identity and assignments

Authentik is the master database for:

- users;
- groups;
- MFA;
- identity lifecycle;
- application/service capability assignment.

V2 does not maintain a duplicate user/group/permission database.

### 5.2 Each V2 service becomes an assignable auth object

Every V2 service automatically exposes a stable service-level access capability.

Recommended canonical identity:

```text
application.<service-id>.access
```

A service may also declare additional **service-scoped capabilities** where the application genuinely has multiple permission levels, for example:

```yaml
authorization:
  capabilities:
    - id: retention
      title: Manage retention
    - id: ingest
      title: Submit data
    - id: admin
      title: Application administration
```

These resolve to stable Authentik-managed capability/group objects such as:

```text
application.metrics-runtime.access
application.metrics-runtime.retention
application.some-service.admin
```

The exact Authentik implementation may use deterministic managed groups or another native Authentik construct, but assignments remain Authentik-owned.

V2 may create/update the capability objects required by the service definition. It must not assign users to them.

### 5.3 Do not create capabilities for every V2 implementation object

V2 must **not** create a parallel authorization universe for every route, listener, storage record, credential object, network profile, timer, or internal implementation detail.

Only service-level access and explicitly declared service capabilities are user-facing authorization concepts.

Native systems retain their own finer-grained policy where appropriate:

- CopyParty handles share/file ACLs;
- application-native roles remain application-native;
- administrative editing of V2 remains an administrator/Cockpit permission;
- firewall/network management remains an administrator operation.

### 5.4 Caddy performs request-time enforcement

For identity-protected HTTP routes, generated Caddy configuration performs the full request-time flow:

1. Strip any forged incoming identity headers.
2. Authenticate through Authentik forward-auth/outpost.
3. Receive trusted Authentik identity/group/capability data.
4. Check the capability required by the service/route.
5. Deny the request if the required capability is absent.
6. If the service is on-demand, invoke the minimal wake mechanism **after** authorization succeeds.
7. Proxy the request.

V2 itself is not called to decide whether a request is allowed.

### 5.5 Caddy owns the user-visible application list

The dynamic landing page/service list is generated from V2 route/portal metadata, but Caddy filters the result using the same trusted Authentik capability information.

A user should see only services/routes they are allowed to access.

There must not be a separate V2 daemon that queries user identity and constructs a second filtered portal.

### 5.6 Upstream-native authentication remains upstream-native

Some services may intentionally use their own authentication or API-key mechanism.

V2 should represent this as routing policy such as `upstream`/native auth, not implement another secret checker.

If Caddy/Authentiк already supports the desired auth policy, use that. Otherwise let the upstream application enforce its native credential policy.

## 6. Service object model

A service is the main V2 unit of application configuration.

Conceptual shape:

```yaml
services:
  example:
    name: Example
    description: Example application
    enabled: true
    managed: true

    workload: ...
    runtime: ...
    dependencies: ...
    readiness: ...
    requiresCapabilities: ...
    authorization: ...
    resources: ...
    sandbox: ...
    storage: ...
    credentials: ...
    network: ...
    routes: ...
    listeners: ...
    backup: ...
    portal: ...
```

The GUI must be able to create/edit all meaningful fields without application-specific UI code.

## 7. Workload model

Workload kind and activation are separate concepts.

### 7.1 Daemon

Long-running service.

```yaml
workload:
  kind: daemon
  activation: persistent
```

or:

```yaml
workload:
  kind: daemon
  activation: on-demand
  idleSeconds: 600
```

Persistent means the native runtime keeps the service running while enabled.

On-demand means V2 generates native configuration so an already-authorized request/action can start the workload and native systemd/timer behavior can stop it after inactivity where supported.

V2 must not run a permanent central reaper.

### 7.2 Job

Finite operation.

```yaml
workload:
  kind: job
  schedules:
    - calendar: daily
      randomizedDelaySeconds: 900
```

or:

```yaml
workload:
  kind: job
  schedules:
    - intervalSeconds: 3600
```

Jobs cover:

- migrations;
- configuration preparation;
- Syncthing reconciliation;
- backup execution;
- restore verification;
- replication;
- update checks;
- one-shot preparation.

Do not add generic `preStart`/`postStart` hook mini-languages. Model meaningful finite operations as jobs and dependencies.

### 7.3 Session

A session is an explicitly created finite runtime instance, useful for disposable per-use workloads such as one-shot conversion or import containers.

The V2 definition describes how to provision/session-template the runtime, resources, mounts, network, and dependencies.

Session workloads require the direct OCI runtime. Other runtime adapters represent shared or persistent owners and cannot provide the per-instance lifecycle boundary required by sessions.

Authentication, identity validation, and permission to start a session remain outside V2 and are enforced by the authenticated launch path.

V2 must not maintain an identity/session authorization database.

Prefer native templated/transient systemd/Podman mechanisms and native cleanup timers over a central session daemon.

## 8. Dependencies

Dependencies are first-class service data and must be runtime-neutral.

```yaml
dependencies:
  - service: ai-config
    condition: completed
  - service: victoriametrics
    condition: ready
```

Conditions:

- `started` — dependency runtime was activated;
- `ready` — dependency passed generic readiness probes;
- `completed` — dependency is a job and completed successfully.

A systemd service can depend on a container, a VM can depend on a systemd service, a Compose application can depend on a job, and so on.

### 8.1 Native lowering

V2 should compile the dependency graph into native systemd ordering/wrapper/target relationships where practical rather than keeping a resident dependency manager.

Systemd is the preferred cross-runtime orchestration spine because Podman, Compose wrappers, libvirt actions, generated jobs, and native services can all be represented by or triggered from units.

### 8.2 Core/platform dependencies

Some dependencies are platform/control-plane substrates and are not owned by V2 lifecycle, for example:

- mounted ZFS;
- Authentik;
- Caddy;
- Podman;
- libvirt;
- network-online.

V2 may reference/check/order against them but must not assume it owns their shutdown lifecycle.

## 9. Readiness

Readiness is generic and declarative.

Supported probes:

- systemd active state;
- TCP connect;
- HTTP status range;
- filesystem path existence.

Example:

```yaml
readiness:
  timeoutSeconds: 60
  intervalMilliseconds: 500
  probes:
    - type: http
      url: http://127.0.0.1:8080/health
      acceptStatusMin: 200
      acceptStatusMax: 399
```

Dependencies use readiness data; there are no application-specific health callbacks.

Where possible, readiness should be compiled into native systemd gating/oneshot checks rather than requiring a permanent V2 process.

## 10. Runtime model

Runtime adapters are thin translators. They do not contain application identities.

### 10.1 Existing systemd

```yaml
runtime:
  type: systemd
  unit: existing.service
```

Use for already-packaged native NixOS units.

One V2 service should have one lifecycle-owning unit. If several units represent meaningful independently ordered work, model them as separate service/job nodes or point at an appropriate systemd target.

### 10.2 Generic executable

```yaml
runtime:
  type: exec
  command:
    - /run/current-system/sw/bin/example
    - --serve
  workingDirectory: /var/lib/example
  restart: on-failure
```

V2 materializes a generic systemd unit from data.

This path must support:

- command and arguments;
- working directory;
- environment;
- existing/dynamic identity;
- restart policy;
- storage;
- credentials;
- CPU/memory/PID limits;
- sandboxing;
- device/GPU ACLs.

### 10.3 Isolated Python venv

Each Python service gets a private venv derived from its service ID, for example:

```text
/var/lib/nas-control/venvs/<service-id>
```

The venv must never modify or share the control-plane Python environment.

Example:

```yaml
runtime:
  type: python
  interpreter: /run/current-system/sw/bin/python3
  dependencies:
    requirementsFile: /var/lib/nas-control/apps/example/requirements.lock
    requireHashes: true
  entrypoint:
    module: example.server
```

Requirements/project files must be constrained to the application's managed source area. One service's dependency environment cannot affect another service.

### 10.4 Quadlet

```yaml
runtime:
  type: quadlet
  source: /var/lib/nas-control/apps/example/example.container
```

The native Quadlet remains application authority. V2 projects only generic additions such as:

- storage;
- network;
- devices/GPU;
- resources;
- sandbox policy where supported.

### 10.5 Compose

```yaml
runtime:
  type: compose
  source: /var/lib/nas-control/apps/example/compose.yaml
```

The application's Compose file remains authority.

V2 generates a secondary override for generic resources/mounts/network/devices where needed.

Any V2 setting that targets one inner Compose service must name that target explicitly.

### 10.6 libvirt VM

```yaml
runtime:
  type: vm
  source: /var/lib/nas-control/apps/example/domain.xml
```

Native domain XML remains authority.

V2 may project:

- virtiofs storage attachments;
- explicit PCI passthrough;
- generic startup/shutdown relationships.

V2 must never infer that removing a service means deleting persistent VM disks.

### 10.7 Direct OCI

Direct OCI execution exists for cases where static Quadlet is insufficient, especially dynamically parameterized disposable sessions.

All `workload.kind: session` definitions must use `runtime.type: oci`.

It must remain generic and minimal.

Use native Podman flags derived from schema data for:

- image/command;
- storage;
- credentials;
- resource limits;
- read-only root/tmpfs;
- GPU/CDI;
- network;
- per-instance container names.

Prefer Quadlet for ordinary persistent container services.

## 11. GPU and device access

GPU access is a generic resource request, not an AI-specific feature.

Example:

```yaml
resources:
  accelerators:
    - kind: gpu
      vendor: any
      quantity: 1
      required: false
      mode: shared
```

Supported concepts:

- vendor: any/NVIDIA/AMD/Intel;
- quantity or all;
- optional vs required;
- shared vs passthrough;
- explicit device selector where needed;
- Compose target when ambiguous.

Runtime lowering examples:

- systemd/exec: device ACLs;
- Quadlet/OCI: native device/CDI access;
- Compose: target-scoped device/CDI override;
- VM: explicit PCI hostdev passthrough.

VM passthrough must require an explicit PCI device and passthrough mode. `auto` must never detach an arbitrary host GPU into a VM.

Any GPU-accelerated application should be able to request an optional GPU and fall back to CPU. Every future application must use exactly the same mechanism.

## 12. Resource limits and sandboxing

Generic service policy may include:

- CPU limit/quota;
- `memoryHighBytes`;
- `memoryMaxBytes`;
- PID limit;
- read-only root;
- tmpfs mounts;
- writable paths;
- Linux capability drop/add policy;
- no-new-privileges;
- runtime-specific isolation.

Do not use a generic `privileged: true` escape hatch when a narrow named host capability or specific device/capability is sufficient.

Native existing services should default to `inherit` sandbox behavior so V2 does not unexpectedly rewrite carefully tuned NixOS hardening.

Generated exec/Python/OCI workloads may use stricter safe defaults.

## 13. Storage model

Storage is represented as named resources plus service attachments.

Example resource:

```yaml
storageResources:
  projects:
    path: /tank/projects
    dataset: tank/projects
    scope: system
    stateClass: authoritative
    capabilities:
      - read
      - write
      - move
      - delete
      - admin
    backup:
      enabled: true
      consistency: zfs-snapshot
    fileBrowser:
      visible: true
```

State classes:

- `authoritative`;
- `derived`;
- `cache`;
- `ephemeral`.

Cache/ephemeral data must not be backed up as authoritative state.

Attachment:

```yaml
storage:
  - resource: projects
    mountPath: /workspace
    access: write
```

Runtime-specific target is supplied only when needed, for example Compose inner-service target or libvirt virtiofs mount tag.

### 13.1 User-specific filesystem authorization

V2 does not authenticate a user and does not decide whether the user is allowed to access a filesystem location.

Where user-scoped file access is needed, use the native identity/file system that already owns it:

- CopyParty for browsable/file-transfer resources and ACLs;
- an authenticated application/session-launch path for application-specific workspace selection;
- trusted Authentik identity propagated by Caddy where the target system supports it.

V2 may provision path templates or runtime templates, but it must not become a subject validator or membership checker.

Filesystem path containment/safety checks remain appropriate when V2 writes or mounts a path; those are filesystem-safety checks, not authorization decisions.

## 14. Credentials and secrets

Secret values never appear in the V2 YAML.

Credentials are file references, normally under `/run/nas-secrets`.

Example:

```yaml
credentials:
  app-env:
    path: /run/nas-secrets/app.env
    required: true
```

Service attachments may consume credentials as:

- mounted files;
- environment files;
- native application file references.

Avoid secret-to-inline-environment expansion where possible.

Request-time API credential verification does not belong in V2. Use Caddy/Authentiк where appropriate or upstream-native auth.

## 15. Network model

V2 describes application network intent; native networking systems implement it.

Example:

```yaml
network:
  mode: isolated
  outboundDefault: deny
  lanAccess: false
  allowedHostPorts:
    - 8080
  allowedEgress:
    - cidr: 0.0.0.0/0
      ports:
        - 443
```

Modes:

- `host`;
- `isolated`;
- `none`.

V2 may generate stable per-service Podman bridge networks and matching firewalld policy.

Host trusted-zone identity is a platform setting, not application data.

## 16. Direct listeners

Direct listeners are separate from HTTP reverse-proxy routes.

This is required for services such as Syncthing, TFTP, NUT server, and other TCP/UDP protocols.

Example:

```yaml
listeners:
  sync:
    protocol: tcp
    exposure:
      port: 22000
    firewall: true
```

Range example:

```yaml
listeners:
  tftp-response:
    protocol: udp
    exposure:
      start: 50000
      end: 50100
    firewall: true
```

V2 compiles these into firewalld/native listener policy.

A listener is not an authorization object for normal users. Firewall editing is an administrator operation.

## 17. HTTP/HTTPS routes and Caddy

Routes describe reverse-proxy behavior and portal metadata.

Conceptual example:

```yaml
routes:
  web:
    target:
      type: http
      host: 127.0.0.1
      port: 3000
    exposure:
      type: path
      paths:
        - /app/
    auth:
      mode: identity
      capability: access
    proxy:
      stripPrefix: /app
    portal:
      visible: true
      category: Applications
      icon: app
```

The route's identity capability is service-scoped. `capability: access` means the service's standard access capability. Another declared service capability may be named when needed.

### 17.1 Route requirements

The generic route model must cover the current stack without application-specific Caddy snippets:

- path prefixes;
- multiple path aliases;
- hostnames/subdomains;
- HTTP/HTTPS upstreams;
- Unix HTTP sockets;
- WebSockets through normal reverse_proxy behavior;
- prefix stripping;
- static request headers;
- trusted identity headers from Authentik;
- request-header removal;
- response headers;
- origin/referrer/header match constraints when required by applications emitting absolute assets/API paths;
- portal visibility metadata;
- public/authenticated/upstream-native policy;
- on-demand wake after authorization.

### 17.2 Header security

Caddy must remove externally supplied identity headers before Authentik handling and only forward trusted identity headers generated by Authentik.

V2 does not inspect those headers afterward for authorization.

## 18. Dynamic landing page / portal

Every route may include portal metadata:

- visible;
- title;
- description;
- category;
- icon;
- order;
- URL/path.

The route/service capability determines who may access it.

Caddy's landing-page integration uses Authentik claims/groups to hide entries the current user cannot access.

The displayed service set and the actual route authorization must use the same capability source so UI hiding is never the security boundary by itself.

## 19. On-demand wake and idle shutdown

On-demand services are supported, but V2 must not become a permanent request-time controller.

### 19.1 Wake

Generated Caddy flow:

1. Authentik authentication.
2. Caddy capability check.
3. Minimal socket-activated wake call.
4. Native service start/dependency activation.
5. Readiness wait or native startup gate where required.
6. Proxy.

The wake endpoint:

- receives a service identity only;
- trusts Caddy's prior authorization;
- does not receive/validate user/group identity;
- contains no application-specific branches;
- should ideally be socket activated and absent from memory when unused.

### 19.2 Idle stop

Prefer generated native systemd timers/oneshots or runtime-native idle mechanisms.

There should be no permanently running central V2 reaper daemon.

Where dependencies need idle coordination, compile the dependency relationships into native units/timers/state files with the smallest generic helper necessary. The helper must manage runtime state only, not authorization.

## 20. Jobs and scheduling

V2 jobs compile to native systemd oneshot services and timers.

Supported scheduling concepts:

- calendar;
- fixed interval;
- randomized delay;
- persistent catch-up behavior.

There is no V2 scheduling daemon.

Examples of workloads to model this way:

- Authentik migrations where V2-managed;
- Syncthing reconciliation;
- Restic backup;
- restore verification;
- Syncoid replication;
- update checks.

Native ZFS platform maintenance may remain outside V2 if it is host substrate policy rather than an application.

## 21. Backup model

Backup is resource-oriented, not application-name-oriented.

Each storage resource declares whether it is backed up and the required consistency method.

Supported consistency concepts include:

- filesystem;
- ZFS snapshot;
- native dump/job;
- none.

Restic consumes the compiled backup resource inventory.

Database consistency work is represented by native tooling or declarative jobs. Do not add backup code such as `if app == vaultwarden` to a central V2 backup engine.

Generated config/cache data should be regenerated, not backed up as authoritative state.

## 22. CopyParty integration

CopyParty remains the file browser/file-transfer/ACL authority.

V2 may project resources marked visible into CopyParty configuration.

V2 must not replace CopyParty's:

- users/groups;
- volumes;
- ACL semantics;
- WebDAV/TFTP access decisions;
- quotas;
- file permission model.

Identity/group assignments continue to originate in Authentik and the existing identity integration.

## 23. Native application configuration

V2 is not a universal application configuration language.

It should not learn the internal config schema of Grafana, Syncthing, Vaultwarden, VictoriaMetrics, etc.

Application-specific configuration remains:

- native app config files;
- native app UI/API;
- referenced artifacts;
- existing Nix package defaults when still platform-owned.

V2 configures how the application is run, connected, exposed, isolated, backed up, and integrated.

If a generated application config file is needed, prefer a generic file/materialization primitive or an ordinary job rather than application-specific Python in the core engine.

## 24. Host/platform capabilities

V2 application definitions may require named platform capabilities.

Example:

```yaml
requiresCapabilities:
  - zfs-mounted
  - smart-readonly
```

Capabilities represent things only NixOS/host setup should provide:

- installed runtime substrate;
- kernel feature;
- hardware driver;
- narrowly scoped privileged helper;
- host-level storage/network facility.

They are not user authorization permissions.

This distinction is important:

- **platform capability**: host can perform SMART read through a restricted helper;
- **service authorization capability**: user may access/manage a V2 service.

Do not mix the two namespaces.

## 25. GUI contract

The Cockpit GUI is the primary editor and must expose the complete practical V2 model.

### 25.1 Generic sections

At minimum:

- identity: name, description, enabled state;
- workload kind and activation;
- schedule;
- runtime type/source;
- dependencies and dependency conditions;
- readiness;
- required platform capabilities;
- service authorization capabilities;
- CPU/memory/PIDs;
- GPU/device requests;
- sandbox/security policy;
- storage resources/attachments;
- credential references;
- network profile/policy;
- direct listeners;
- Caddy routes;
- portal metadata;
- backup policy;
- advanced native-runtime fields.

### 25.2 No application-specific forms

The frontend may have generic widgets such as:

- service picker;
- runtime picker;
- GPU selector;
- mount editor;
- route editor;
- capability editor;
- dependency graph display;
- timer editor.

It must not have a bespoke `if app == grafana` form.

### 25.3 Validation UX

Schema validation errors should map directly to GUI fields and include:

- readable field path;
- error message;
- invalid value where safe;
- dependency-cycle explanation;
- unavailable platform capability;
- route/listener conflict;
- runtime-specific invalid combination.

The GUI should validate before save and the backend must validate again before apply.

### 25.4 Transactional save/apply

The GUI workflow should be:

1. Edit draft.
2. Validate schema/semantics.
3. Show apply plan when meaningful.
4. Atomically write desired state.
5. Apply native projections.
6. If projection validation fails, retain/recover the previous valid desired/native configuration where safe.
7. Surface the exact failure in Cockpit.

## 26. Seed-once migration from Nix options

During installation/upgrade, NixOS may generate initial V2 desired state from existing options.

Rules:

1. Seed only when no V2 desired-state authority exists.
2. Convert values to resolved YAML values.
3. Never continuously regenerate the file from Nix options.
4. After seed, Cockpit/V2 YAML is the application desired-state authority.
5. Existing Nix app options become compatibility inputs/read-only/deprecated during migration.
6. Remove them once the compatibility window closes.

This avoids two mutable application configuration databases.

## 27. Built-in workload mapping

The following existing services must be expressible without per-application V2 controller code.

### 27.1 Core/platform outside normal V2 ownership

Remain platform/control-plane substrates where necessary:

- ZFS unlock/mount guard;
- PostgreSQL required by Authentik;
- Authentik core server/worker where needed for V2/Cockpit access;
- Caddy ingress;
- Cockpit recovery/admin shell;
- Podman runtime;
- libvirt/QEMU runtime;
- required secret-unlock/bootstrap machinery;
- native ZFS maintenance that is platform policy.

They may appear as referenceable dependency nodes/capabilities, but V2 does not own their shutdown lifecycle.

### 27.2 Application workloads to represent in V2

- CopyParty;
- Syncthing;
- Syncthing reconciliation job;
- Vaultwarden;
- Vaultwarden CA preparation job;
- VictoriaMetrics;
- Telegraf;
- vmalert;
- Alertmanager;
- alertmanager-ntfy;
- Grafana;
- ntfy;
- NUT WebGUI;
- Restic backup job;
- restore verification;
- Syncoid replication;
- optional update jobs;
- future user-added applications.

### 27.3 Important dependency examples

- Grafana depends on started VictoriaMetrics;
- Telegraf depends on VictoriaMetrics;
- Vaultwarden depends on the completed CA preparation job and identity platform capability;
- Syncthing depends on mounted storage/network;
- reconciliation jobs depend on the relevant daemon being ready.

## 28. Minimal example: metrics runtime + dashboards

Illustrative only; exact fields follow the canonical JSON Schema.

```yaml
schemaVersion: 3

services:
  metrics-storage:
    name: Metrics storage preparation
    enabled: true
    workload:
      kind: job
    runtime:
      type: systemd
      unit: nas-metrics-storage.service

  metrics-runtime:
    name: Metrics database
    enabled: true
    workload:
      kind: daemon
      activation: on-demand
      idleSeconds: 600
    runtime:
      type: systemd
      unit: nas-metrics.service
    dependencies:
      - service: metrics-storage
        condition: completed
    resources:
      accelerators:
        - kind: gpu
          vendor: any
          quantity: 1
          required: false
          mode: shared
    readiness:
      probes:
        - type: tcp
          host: 127.0.0.1
          port: 8080
    authorization:
      capabilities:
        - id: retention
          title: Manage retention
    routes:
      ui:
        target:
          type: http
          host: 127.0.0.1
          port: 8080
        exposure:
          type: path
          paths:
            - /metrics/admin/
        auth:
          mode: identity
          capability: access
        portal:
          visible: true
          category: Monitoring
      api:
        target:
          type: http
          host: 127.0.0.1
          port: 8080
        exposure:
          type: path
          paths:
            - /metrics/api/
        auth:
          mode: upstream

  dashboards:
    name: Dashboards
    enabled: true
    workload:
      kind: daemon
      activation: on-demand
      idleSeconds: 600
    runtime:
      type: systemd
      unit: dashboards.service
    dependencies:
      - service: metrics-runtime
        condition: ready
    routes:
      main:
        target:
          type: http
          host: 127.0.0.1
          port: 3000
        exposure:
          type: path
          paths:
            - /metrics/
        auth:
          mode: identity
          capability: access
        portal:
          visible: true
          category: Monitoring
```

Nothing in the generic compiler needs to know what the metrics database or the dashboard application is.
