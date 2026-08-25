# Code map

## NixOS module

| Area | Primary files | Notes |
|---|---|---|
| Options | `modules/nas/options/*.nix`, `modules/ai/options.nix` | Public appliance configuration contract. |
| Validation | `modules/nas/config/validation.nix`, `modules/ai/validation-identities.nix` | Evaluation-time safety assertions. |
| Core services | `modules/nas/config/systemd-services.nix`, `application-services.nix` | Native upstream applications and appliance units. |
| Managed Services V2 | `managed-services.nix`, `managed-services-seed-v2.nix`, `managed-services-helpers.nix`, `managed-services-lifecycle.nix`, `managed-services-authentik-blueprint.nix`, `managed-services-backup-profile.nix`, `managed-services-compose-import.nix`, `managed-services-generations.nix`, `managed-services-network-platform.nix`, `managed-services-transactions.nix` (all under `modules/nas/config/`) | Single complete V3 seed (baseline + operations + backup + platform), seed-once bootstrap, finite reconciliation; no continuous regeneration. Shared helpers (`daemon`, `job`, `portListener`, etc.) live once in `managed-services-helpers.nix`; generations, transactions, backup, network, compose-import, and blueprint fragments are split per concern but aggregated in the seed. |
| Proxy/auth | `modules/nas/config/reverse-proxy.nix`, `caddy-bootstrap.nix`, `modules/nas/internal/caddy-helpers.nix`, `services/nas_v2_caddy.py` | Caddy + Authentik trusted-header and request-time authorization boundary. `caddy-bootstrap.nix` selects static setup guidance before activation and the managed configuration after it; app routes are data in `services.yaml`, not Caddy branches. |
| Storage | `modules/nas/config/storage-monitoring.nix`, `modules/nas/internal/zfs-tools.nix` | ZFS, snapshots, restore verification, replication, and Restic integration. |
| Observability | `modules/nas/config/observability.nix` | VictoriaMetrics, Telegraf, vmalert, NAS alert router, optional Grafana/ntfy. |
| Identity/capability policy | `services/nas_v2_authentik_blueprint.py`, `schemas/managed-services-v3.schema.json` | Appliance identity capability/group contract; V2 creates `application.<service>.<capability>` objects, never assignments. |
| Coding agent | `modules/ai/coding-agent.nix`, `services/nas_coding_agent.py` | Transient `nas-code-agent` sandbox, `pi-coding-agent` package, workspace-allowlisted `nas-code` launcher, llama-swap client-credential isolation. |
| Command packaging | `modules/nas/internal/account-tools.nix` | Installs Python tools (`nas-managed-services`, `nas-managed-services-control`, `nas-code-agent`), finite V2 control aliases, portal assets, and Authentik blueprint. |
| Documentation/UI packaging | `modules/nas/internal/documentation-tools.nix` | Builds mdBook references and the Cockpit plugin. |

`modules/nas/internal/default.nix` merges internal contexts with duplicate-name detection. New helpers should stay local unless multiple configuration modules consume them.

Managed Services V2 has one mutable desired-state authority: `/var/lib/nas-control/services.yaml` (revision = sha256 of exact bytes). `JSON Schema` at `/etc/nas-control/managed-services-v3.schema.json` is the structural/UI contract. The baseline, operation, backup, and platform declarations are all aggregated into `managed-services-seed-v2.nix` with shared data/helper definitions in `managed-services-helpers.nix` (imported, not duplicated); the restic timer override and native-dump services live beside the Restic service in `storage-monitoring.nix`. `features.json` is gone.

## Python services

| Entry point/module | Responsibility | Main tests |
|---|---|---|
| `nas_setup.py` | First-run orchestration, guarded storage creation, runtime account commands | `test_setup.py` |
| `nas_setup_config.py` | Setup schema, normalization, and secure secret-file input | `test_setup.py` |
| `nas_identity_sync.py` | Authentik and Syncthing I/O/reconciliation entry point | `test_identity_sync.py` |
| `nas_identity_model.py` | Pure identity, account-plan, and Syncthing desired-state model | `test_identity_sync.py` |
| `nas_cockpit_api.py` | Fixed privileged action allow-list for the Authentik-authorized Cockpit session | `test_cockpit_api.py` |
| `nas_operation_lock.py` | Shared cross-process conflict classes and reconnect-safe active-operation metadata | `test_operation_lock.py`, `test_cockpit_api.py` |
| `nas_operation_journal.py` | Durable resumable-operation phases and manual-recovery stop semantics | `test_setup.py`, `test_identity_sync.py` |
| `nas_state.py` | Signed profile-aware state export, drift, validation, rollback, and restore | `test_state.py`, `test_v2_state_authority.py` |
| `nas_doctor.py` | Unified appliance diagnostics and V2 desired/effective drift detection (absorbs legacy state-authority migration checks) | `test_doctor.py` |
| `nas_syncthing_devices.py` | Narrow user-attribute parser/validator | `test_syncthing_devices.py` |
| `nas_common.py` | Shared appliance parsing and policy helpers | `test_common.py`, `test_contract_identity.py` |
| `nas_alert_router.py` | Bounded vmalert notification routing, status, deduplication, and optional ntfy delivery | `test_alert_router.py` |
| `nas_logging.py` | Redacted bounded JSON operation records for journald | `test_logging.py` |
| `nas_v2_spec.py` | YAML 1.2 parsing (rejects empty/null), V3 schema validation, normalization, semantic validation, and effective-state compilation | `test_v2_spec.py` |
| `nas_v2_bootstrap.py` | Seed-once: validates one complete V3 seed and atomically creates `services.yaml` once (with flock) | `test_v2_bootstrap.py`, `test_v2_seed_aggregation.py` |
| `nas_v2_plan.py`, `nas_v2_apply.py` | Deterministic plan generation and finite transactional file apply (bundle + rollback) | `test_v2_plan_apply.py` |
| `nas_v2_entry.py` | V2 command-surface entry/import boundary | `test_v2_boundary.py` |
| `nas_v2_control.py`, `nas_v2_editor.py` | Finite status/document/edit/reconcile API, revision-safe CAS (sha256), comment-preserving atomic edits | `test_v2_editor.py`, `test_v2_revision.py` |
| `nas_coding_agent.py` | Workspace-allowlisted `nas-code` session launcher, credential isolation, systemd-run sandbox | `test_coding_agent.py` |
| `nas_v2_systemd.py` | Unified systemd lowering for cross-runtime lifecycle, dependencies, jobs, readiness, attachments, leases, and idle timers | `test_v2_systemd.py` |
| `nas_v2_systemd_native.py`, `nas_v2_systemd_attachments.py`, `nas_v2_systemd_reconcile.py`, `nas_v2_activation.py`, `nas_v2_generation.py` | Native systemd unit generation, attachment wiring, reconciliation, activation ordering, and generation bookkeeping | `test_v2_systemd*.py`, `test_v2_generation.py`, `test_v2_restore_wiring.py` |
| `nas_v2_quadlet.py` | Direct OCI/Quadlet projection | `test_v2_quadlet.py` |
| `nas_v2_compose.py`, `nas_v2_compose_import.py` | Compose override projection and legacy compose import for V2-owned cross-cutting policy | `test_v2_compose.py`, `test_v2_compose_systemd.py`, `test_v2_compose_projection.py` |
| `nas_v2_libvirt.py` | Libvirt/QEMU projection and explicit passthrough policy | `test_v2_libvirt.py` |
| `nas_v2_session.py` | Finite transient-session launch plus descriptor/resource/network projection; Podman is the direct systemd exec process (`ExecStopPost` cleanup, no supervisor process) | `test_v2_session.py`, `test_v2_session_projection.py` |
| `nas_v2_accelerator.py` | Generic accelerator resolution for device nodes, CDI, Compose targets, and VM passthrough (candidate for `hardware.nvidia` + CDI) | `test_v2_accelerator.py` |
| `nas_v2_network.py`, `nas_v2_podman_network.py`, `nas_v2_firewalld_reconcile.py`, `nas_v2_nmstate.py` | Combined V2 network policy: isolated Podman networks, firewalld policy, and NMState wiring (candidate for static `networking.firewall` absorption) | `test_v2_podman_network.py`, `test_v2_firewalld.py`, `test_v2_network_semantics.py`, `test_v2_nmstate.py` |
| `nas_v2_authentik_blueprint.py` | Generates stable `application.<service>.<capability>` objects without owning assignments | `test_v2_authentik_blueprint.py` |
| `nas_v2_caddy.py` | Request-time routing/auth projection (generic `proxy.*`, `requireHeaders`, `stripPrefix`, `onDemandWake`) | `test_v2_caddy.py` |
| `nas_v2_backup.py` | Resource-oriented backup inventory and finite preparation/cleanup jobs (freshness via stale-clear); absorbs the former runtime/native-dump modules | `test_v2_backup.py`, `test_v2_backup_runtime.py`, `test_v2_native_dump.py` |
| `nas_v2_readiness.py`, `nas_v2_exec_runner.py`, `nas_v2_source_watch.py`, `nas_v2_history.py`, `nas_v2_platform_probe.py` | Readiness probes, exec running, source watching, generation history, and platform capability probing | `test_v2_readiness.py`, `test_v2_exec_runner.py`, `test_v2_source_watch.py`, `test_v2_history.py`, `test_v2_platform_ownership.py` |

There is no `nas_feature_control.py` implementation and no installed `nas-feature-control` command; tests assert their absence. Do not restore the deleted gate/controller/reaper architecture to satisfy old tests or documentation.

Pure policy and schema helpers should contain no service-management side effects. Runtime adapters project normalized V3 state into native mechanisms and fail closed when a requested semantic cannot be represented.

## Front end

- `cockpit/src/index.jsx`: React 18 entry point, PatternFly stylesheet imports, and Cockpit dark-theme sync.
- `cockpit/src/cockpit-dark-theme.js`: Cockpit theme bridge imported by the entry point.
- `cockpit/src/app.jsx`: single-page shell — section registry (`PAGES`), stock PatternFly `Nav`, alert stack, and the secrets-unlock card.
- `cockpit/src/pages/`: one module per UI section (overview, services, applications, operations, ai, source, setup — 7 pages); adding a section means one file plus one `PAGES` entry.
- `cockpit/src/components/`: shared presentation components (status label, output block, section header, link/service cards).
- `cockpit/src/hooks/`: `use-overview` data fetch and `use-mutation` busy/error/notice wrapper shared by all pages.
- `cockpit/src/schema-editor.jsx`, `cockpit/src/schema-model.js`: schema-driven desired-state form generated from the canonical V2 JSON Schema.
- `cockpit/src/systemd.js`: systemd timer/unit helpers for the UI.
- `cockpit/src/api.js`: allowed Cockpit bridge invocations, including finite Managed Services document/status/edit calls and stdin-only secret delivery after browser authorization.
- `cockpit/src/view-model.js`: pure backend-to-view conversion and visibility policy.
- `cockpit/src/lib/format.js`: error-message and JSON display helpers.
- `cockpit/src/app.scss`: NAS-specific layout only; PatternFly owns component styling.
- `cockpit/build.js`: Starter Kit style esbuild/Sass source-to-package build and source-hash stale-output check.
- `cockpit/dist/`: generated React/PatternFly package payload installed by Nix; never edit it directly.
- `web/portal/index.html` and `lib/web/portal-static/setup.html`: Caddy templates, not application services.

Pure Cockpit API and view-model behavior has direct Node coverage. JSX component composition is checked structurally and through the built browser package in CI.

## Validation

- `scripts/preflight.sh`: small validation orchestrator.
- `scripts/validate-structure.py`: generic repository shape/version checks.
- `scripts/validate-repository-data.py`: JSON/TOML/schema checks.
- `tests/test_contract_*.py`: cross-file architecture and security contracts.
- `tests/test_browser_authz.py`, `tests/browser/authz.py`, `tests/vm/guest-test.sh`: browser authorization, no-direct-Cockpit, and locked-boot recovery checks.
- `tests/test_v2_*.py`: V3 compiler, adapter, reconciliation, resource, session, and authority contracts.
- `scripts/qemu-test.sh`: native NixOS tests and full ISO install/reboot test.
