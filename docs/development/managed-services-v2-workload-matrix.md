# Managed Services V2 workload matrix

This inventory derives the canonical V2 application contract from the workloads that NixOS NAS already runs. A V2 primitive is justified only when an existing or clearly planned workload requires it. Application-specific controller branches are not acceptable substitutes for missing primitives.

## Boundary

V2 owns application desired state and application lifecycle. NixOS continues to own host/platform capabilities that applications consume: kernel/drivers, Podman, libvirt, ZFS, system packages, trusted privileged helper capabilities, and the minimal unlock/identity/ingress control plane required to operate V2 itself.

A new application that uses existing V2 runtimes and host capabilities must require only declarative V2 data plus the application's own native configuration/source. Adding a new *generic host capability* or a new runtime kind may require platform code.

## Existing workloads

| Workload | Shape today | Requirements the V2 spec must express |
|---|---|---|
| PostgreSQL for Authentik | NixOS service | core/platform dependency; existing systemd unit; local socket; authoritative database state; native dump backup |
| Authentik migration | systemd oneshot | **job**; depends on PostgreSQL; secret environment file; writable state path; retry/restart-on-failure; successful completion gates server/worker |
| Authentik worker | systemd daemon | daemon; existing systemd unit; depends on completed migration; secret file; state directory; hardened sandbox |
| Authentik server | systemd daemon | daemon; depends on migration/worker; HTTP readiness probe; identity endpoint; path-prefix ingress; file state + PostgreSQL |
| Caddy | NixOS service | core ingress substrate; existing systemd unit; generated routes from all V2 endpoints; internal CA consumed by Vaultwarden helper |
| Cockpit | socket-activated system service | core/recovery substrate; existing systemd socket; ingress endpoint |
| CopyParty | NixOS service | daemon; ZFS/storage dependency; unix-socket endpoint; multiple ingress routes with different auth; WebDAV; TFTP UDP/range exposure; identity headers; storage projection; mDNS discovery |
| Syncthing | NixOS service | daemon; ZFS dependency; network-online; read/write user share storage; GUI endpoint; sync protocol ports; persistent identity/config files; generated device/folder reconciliation job |
| Syncthing reconciliation | systemd oneshot/timer | job; depends on Authentik + ready Syncthing; secret token file; periodic trigger; successful completion |
| Vaultwarden CA export | systemd oneshot | job; depends on Caddy; creates a runtime CA file; completion gates Vaultwarden |
| Vaultwarden | NixOS service | daemon; depends on identity + CA job; SQLite state; secret environment file; native OIDC configuration; several ingress routes with different auth policy; WebSockets |
| AI storage preparation | systemd oneshot | job; depends on mounted ZFS; creates directories/permissions; completion gates AI apps |
| llama-swap | systemd daemon | on-demand daemon; depends on AI storage/config jobs; optional GPU acceleration; state/cache storage; secret environment file; API-key and admin UI endpoints; readiness probe; graceful signal/restart policy |
| AI config initialization | systemd oneshot | job; depends on AI storage; idempotent file materialization/migration; completion gates llama-swap |
| Open WebUI | NixOS service | on-demand daemon; depends on ready llama-swap + AI storage; persistent state; secret env file; identity-authenticated ingress; proxy headers/path prefix; readiness |
| Hugging Face downloader | Podman service | on-demand container; depends on AI storage; secret env file; persistent downloader/model cache; read-only/security constraints; route aliases for apps that emit absolute asset/API paths |
| Pi coding agent | disposable Podman session | **session**; depends on ready llama-swap; authenticated user-scoped state; selected workspace; read-only credential mount; CPU/memory/PID limits; restricted network; optional tools; generic session lease |
| Future Starlight server | unspecified runtime | must be expressible with the same daemon/session/job + dependency + accelerator + endpoint primitives; no Starlight controller code |
| VictoriaMetrics | NixOS service | persistent daemon; loopback endpoint; state; memory limit; retention config; readiness |
| Telegraf | NixOS service | persistent daemon; depends on ready VictoriaMetrics; resource limits/hardening; requires named platform capability for restricted SMART helper; host metrics access |
| vmalert | NixOS service | persistent daemon; depends on VictoriaMetrics + alert receiver; generated rules file; loopback endpoint/readiness |
| NAS alert router | generic executable systemd service | daemon; optional dependency on ntfy; state file; file credentials; strict sandbox; HTTP readiness; generic exec runtime must be sufficient |
| Grafana | NixOS service | on-demand daemon; depends on VictoriaMetrics; file secret; persistent state; generated datasource/dashboard config; identity proxy headers; path-prefix ingress; readiness |
| ntfy | NixOS service | persistent daemon; file secret/env; persistent cache/attachments; upstream-native client auth; ingress path |
| NUT WebGUI | Podman container | on-demand container; host network; secret mounts; read-only root; tmpfs; memory/PID limits; upstream UPS dependency; ingress |
| Restic system backup | systemd timer + oneshot | scheduled **job**; resource-derived backup inventory; consistent pre-jobs/native dumps; ZFS snapshots; credential file; retention/check policy; no resident V2 daemon |
| Backup restore verification | systemd timer + oneshot | scheduled job; isolated scratch storage; depends on repository; PostgreSQL/SQLite validation commands; cleanup |
| Syncoid replication | systemd oneshot/timer | scheduled job; depends on mounted ZFS + network; configurable command arguments; resource/mount assertions |
| Sanoid/ZFS scrub/trim | native NixOS timers | platform maintenance jobs; can be cataloged/referenced by V2 when useful but are ZFS substrate rather than applications |
| Automatic update | systemd timer | scheduled job; existing native unit or generic exec; must never require a bespoke lifecycle controller |
| libvirt | NixOS service | runtime substrate required by V2 VM adapter; stays platform-managed |
| VM storage preparation/pool | oneshot helpers | platform/runtime-substrate jobs; V2 VMs depend on libvirt/storage capability rather than duplicating them per VM |

## Generic primitives required by the matrix

### Workload model

A service declares one workload kind:

- `daemon` — long-running process; activation is `persistent` or `on-demand`.
- `session` — runtime exists for explicit V2 session leases.
- `job` — finite execution; may be invoked manually, by dependency, or by schedule.

This replaces the attempt to force one-shot work into daemon lifecycle modes.

### Dependencies

Dependencies are service references with conditions:

- `started` — native runtime activation completed.
- `ready` — dependency readiness probes succeeded.
- `completed` — dependency is a job and completed successfully.

References may cross runtime kinds and runtime implementations. There is no per-application wake code.

### Runtime implementations

- existing systemd unit(s)
- generic executable materialized as a transient/generated systemd service/job
- native Quadlet source
- native Compose source
- native libvirt XML

A new application using these requires no runtime-adapter code.

### Host capabilities

Applications reference named host capabilities rather than embedding privileged host setup. Examples include:

- `zfs-mounted`
- `network-online`
- `smart-readonly`
- `podman`
- `libvirt`
- `gpu`

Capability definitions are platform/NixOS responsibility. This is the escape hatch for host-level privileges without app-specific controller branches.

### Storage

Named resources describe path/dataset, scope (`system`, `user`, `instance`), state class, backup policy, and file-browser visibility. Attachments provide access and runtime-local target/mount information.

### Credentials

Credentials are references to files under `/run/nas-secrets`. Secret values never appear in the application document. Attachments select mount/file destinations. Native apps may reference the file path directly.

### Accelerator/device access

Structured requests describe GPU/device intent: optional/required, shared/passthrough, vendor/quantity or explicit PCI/CDI identity, and optional Compose target. Host discovery resolves requests; adapters project the resolved device policy.

### Network/exposure

Network policy covers host/isolated networking, LAN access, allowed egress/host ports, and exposed protocol ports/ranges. Endpoint routes cover HTTP(S)/WS/Unix/TCP/UDP targets, path/hostname/port exposure, proxy prefix transforms, headers, authorization, and optional service discovery metadata.

### Readiness

Generic probes: systemd state, TCP, HTTP, path. Readiness is the only mechanism dependency code uses; there are no application-specific health callbacks.

### Security/resources

Generic exec/container runtime policy must cover CPU, memory, PIDs, read-only root/tmpfs, security profile, writable paths, device access, and a small named platform-capability set for privileges that cannot safely be inferred.

### Scheduling

Jobs may have zero or more calendar triggers. V2 projects them to native systemd timers. A job is still invokable directly regardless of schedule.

### Backup

Backup remains resource-oriented. Consistency work is represented by ordinary V2 jobs/resources where possible; Restic consumes the normalized backup inventory. PostgreSQL/SQLite commands live in declarative job definitions/native tooling rather than application-named backup code.

## Ingress cases that must be representable without raw Caddy snippets

The endpoint model must cover all current route behavior:

- strip path prefix before proxying
- set static or trusted-identity-derived request headers
- set/remove response headers
- forward WebSockets
- multiple routes to one service with different auth policies
- header/referrer/origin match constraints for absolute asset/API aliases
- Unix-socket upstreams
- public, identity-capability, secret credential, and upstream-native authorization
- HTTP path/hostname and raw TCP/UDP port/range exposure
- optional mDNS metadata

If a current route requires a raw Caddy fragment after the final schema is implemented, the endpoint model is incomplete.

## Authoring and validation format

Canonical human/admin format: **YAML 1.2**.

Canonical structural/UI contract: **JSON Schema 2020-12**.

Processing pipeline:

1. Parse YAML 1.2 strictly; duplicate mapping keys are errors.
2. Validate the parsed data against the canonical JSON Schema.
3. Apply deterministic defaults in one normalizer.
4. Perform semantic validation: cross-references, dependency cycles, runtime-specific constraints, capability/resource existence.
5. Resolve host resources/capabilities into an effective document under `/run`.
6. Drive native adapters/projections only from the effective document.

JSON remains valid import input because JSON is compatible with YAML 1.2. The persisted desired-state file is YAML so administrators retain comments and readable diffs.

## Acceptance rule

After migration, adding a new application such as Starlight must require only:

1. adding/editing its V2 YAML service/resource definitions;
2. supplying the application's native source/config artifact if the chosen runtime has one;
3. selecting existing host capabilities.

No Python/Nix/Cockpit/Caddy-specific application branch is permitted. If one is required, either the spec lacks a generic primitive or the application needs a genuinely new platform capability/runtime adapter that should be designed generically first.
