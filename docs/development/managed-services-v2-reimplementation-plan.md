# Managed Services V2 reimplementation plan

This plan supersedes the incremental wrapper-first V2 plan. It is derived from the current workload matrix and the iterative spec critique in `managed-services-v2-spec-review.md`.

## End state

`/var/lib/nas-control/services.yaml` is the mutable application desired-state authority.

`/etc/nas-control/managed-services-v3.schema.json` is the structural validation and GUI-form contract.

`/etc/nas-control/platform-capabilities.json` is immutable NixOS-published host capability inventory.

`/run/nas-control/effective.json` is the normalized/resolved runtime view and is never edited or backed up as authority.

The system has no resident V2 controller. Reconcile/path/timer/socket activation remains systemd-owned.

Adding an application using an existing runtime/capability requires only the YAML definition plus its native application artifact/configuration. No application-specific Python, Nix lifecycle, Caddy branch, Cockpit form, or backup branch.

## Phase 1 — freeze the workload-derived contract

1. Keep the canonical authoring format YAML 1.2.
2. Keep JSON Schema 2020-12 as validation/UI contract.
3. Model workload kind explicitly: daemon, job, session.
4. Keep dependencies structured and cross-runtime with started/ready/completed conditions.
5. Keep readiness generic: systemd/TCP/HTTP/path.
6. Keep host privileges behind reusable named platform capabilities.
7. Keep credentials file-referenced only.
8. Keep GPU/device requests structured and runtime-neutral.
9. Cover all existing ingress transforms without raw Caddy application snippets.
10. Keep session path selection generic enough to replace Pi workspace-specific launcher code.
11. Do not add lifecycle hook or arbitrary configuration-template languages.
12. Reject any proposed field whose only justification is one application name; find the generic workload primitive instead.

Exit criterion: every row in `managed-services-v2-workload-matrix.md` can be represented without application-specific controller behavior.

## Phase 2 — one canonical loader/normalizer

Replace duplicated validation/default behavior with `nas_managed_spec.py`:

1. Strict YAML 1.2 parser; duplicate keys rejected.
2. JSON Schema validation with precise document paths.
3. Deterministic defaults independent of JSON Schema annotation behavior.
4. Semantic checks:
   - storage/credential/network/capability references;
   - dependency cycles and condition correctness;
   - user/instance path-template rules;
   - endpoint authorization references;
   - runtime-specific accelerator/target constraints;
   - session-input constraints;
   - unsafe paths.
5. Normalize to a plain JSON-compatible dictionary.

Package the parser and validator dependencies in the Nix Python closure before the live engine imports this module.

## Phase 3 — collapse the engine wrapper stack

Replace `legacy -> v2 -> devices -> dependencies -> readiness` monkey-patching with one engine module using the normalizer and small helper modules.

The engine owns only:

- dependency DAG ordering;
- daemon persistent/on-demand activation;
- jobs and completion state;
- generic session leases;
- readiness waiting;
- idle reaping;
- start/stop/run/session commands;
- projection/reconcile transaction ordering.

It does not know application IDs.

Keep helpers pure where possible so they are easy to fuzz/property-test.

## Phase 4 — platform capability inventory

NixOS publishes availability of reusable host capabilities. Initial capabilities come from the current workload audit:

- `network-online`
- `zfs-mounted`
- `podman`
- `libvirt`
- `kvm`
- `smart-readonly`
- GPU runtime/driver availability as appropriate

Startable core dependencies such as Caddy/AuthentiK may remain service nodes with `managed: false`; V2 may ensure and readiness-check them but never reaps/stops them.

A capability is not an application. New privileged host behavior must be added here generically rather than as a service-name exception.

## Phase 5 — thin runtime adapters

### Existing systemd

- start/stop existing units;
- generated `/run/systemd/system/<unit>.d/` policy only for V2-owned generic resource/device overrides;
- no rewriting Nix-owned unit definitions.

### Generic exec

Materialize a transient/generated systemd unit from spec data:

- command/working directory/environment;
- dynamic or existing identity;
- restart/stop policy;
- resource limits;
- sandbox profile;
- storage/credential access;
- network restrictions where systemd can enforce them.

This path is sufficient for a future application whose package/binary already exists without adding a Nix service module.

### Quadlet

Keep native `.container` authority. V2 projects only storage/network/device/resource policy through generated drop-ins and installs the application natively.

### Compose

Keep native Compose authority. V2 generates one secondary override for storage/network/device/resource additions and requires explicit inner-service target where ambiguous.

### libvirt

Keep native domain XML authority. V2 generates `/run` projection for virtiofs and explicit PCI host devices; persistent disk ownership/deletion is never inferred.

### OCI session

A minimal `podman run --rm` adapter exists only for dynamic session inputs/identity/instance mounts that static Quadlet cannot represent safely. It is generic and replaces the Pi-specific container launcher.

## Phase 6 — generic scheduled jobs

Jobs may have systemd calendar triggers. V2 generates timer/service units under `/run` or uses transient timers.

Migrate:

- Syncthing reconciliation timer;
- Restic backup trigger;
- backup restore verification;
- Syncoid replication;
- update checks where still desirable.

Native NixOS ZFS maintenance may remain platform-managed when it is a substrate policy rather than an application.

## Phase 7 — generic projections

### Caddy

Generate routes solely from endpoints:

- target + exposure;
- auth;
- matches;
- prefix stripping;
- trusted identity/static/request-header projection;
- response headers;
- Unix/TCP/HTTP transport;
- raw port/range exposure where applicable.

Delete application-specific reverse-proxy branches once all current routes are representable.

### Authentik

Generate required application capability groups from identity-auth endpoints. Membership remains Authentik-owned.

### CopyParty

Generate visible storage volumes from storage resources/capabilities; user-scoped paths use authenticated identity resolution only.

### Restic

Consume backup-enabled resource inventory. Consistency preparation is represented by ordinary V2 jobs/resources rather than application-name branches.

### Discovery/firewall

Derive raw port/range firewall intent and optional mDNS entries from endpoint definitions.

## Phase 8 — prove the model with the AI vertical slice

Re-express, in YAML only:

1. AI storage preparation — job.
2. AI config initialization — job depending on storage job.
3. llama-swap — on-demand daemon depending on completed config job, optional GPU request, file credential, readiness, API/admin endpoints.
4. Open WebUI — on-demand daemon depending on ready llama-swap.
5. model downloader — on-demand OCI/Quadlet service depending on AI storage.
6. Pi — session OCI workload depending on ready llama-swap, user-scoped state, generic path input, credential mount, resource/network limits.

Exit criterion: changing these services' dependency order, GPU policy, idle TTL, endpoints, storage, or enable state requires YAML only.

## Phase 9 — migrate the rest of the current workload matrix

Migrate application desired state in this order:

1. CopyParty.
2. Syncthing + reconciliation job.
3. Vaultwarden + CA-export job.
4. VictoriaMetrics + Telegraf.
5. vmalert + alert router + ntfy.
6. Grafana.
7. NUT WebGUI.
8. backup/verification/replication/update jobs.

Authentik/Caddy/Cockpit/PostgreSQL/ZFS/Podman/libvirt remain minimal platform/control-plane nodes where required for V2 to operate, but their endpoints/readiness may still be represented in the effective graph.

## Phase 10 — migrate current Nix settings into V2

During upgrade/first-run:

1. Read current Nix application options.
2. Produce equivalent V2 YAML exactly once when no V2 authority exists.
3. Preserve administrator changes thereafter.
4. Mark old application options deprecated/read-only compatibility inputs.
5. Remove them after the compatibility window.

There is no YAML interpolation against live Nix values. Persisted desired state contains resolved values.

## Phase 11 — schema-driven Cockpit UI

The V2 Cockpit UI reads JSON Schema + current YAML/effective document.

Generic forms cover:

- enable/managed status;
- workload/activation/schedules;
- dependencies and readiness;
- runtime selection/source;
- host capabilities;
- CPU/memory/PIDs/GPU;
- sandbox;
- storage/credentials;
- network;
- endpoints/auth/proxy/discovery;
- session path inputs.

Use schema `title`, `description`, enum/default and conditional validation. The frontend may add layout hints, but it must not contain application-name forms.

Application-native configuration is edited through the upstream UI or a generic referenced-artifact editor; V2 does not learn application config schemas.

## Phase 12 — delete superseded custom code

After parity tests pass, remove:

- legacy feature lifecycle/apply/reaper state;
- application-specific Caddy routes;
- Pi-specific dependency/heartbeat/container launcher logic;
- duplicated lifecycle wrapper modules;
- static app backup path lists/native app-name backup branches where jobs/resources replace them;
- duplicate Cockpit feature settings;
- old JSON V2 store after YAML migration;
- compatibility registry aliases and `startPolicy` migration fields.

## Validation gates

Every phase must keep the working pre-build CI gates green. Add tests for:

- schema examples for every current workload;
- YAML duplicate keys/type edge cases;
- dependency cycles and job/daemon/session condition rules;
- cross-runtime dependencies;
- readiness failure/timeout;
- session lease begin/touch/end and dependency reaping;
- GPU optional/required/vendor/PCI/CDI cases;
- storage identity/path escape;
- secret non-leakage;
- endpoint route generation for every current Caddy route shape;
- generated systemd/Quadlet/Compose/libvirt policy;
- schedule generation;
- migration equivalence from existing settings;
- GUI round-trip: YAML -> normalized -> form edit -> YAML -> same normalized semantics.

The build/post-build/VM stages become mandatory as they are repaired; GitHub runner infrastructure failures remain distinguished from branch regressions.
