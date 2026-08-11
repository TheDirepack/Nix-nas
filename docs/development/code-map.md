# Code map

## NixOS module

| Area | Primary files | Notes |
|---|---|---|
| Options | `modules/nas/options/*.nix`, `modules/ai/options.nix` | Public appliance configuration contract. |
| Validation | `modules/nas/config/validation.nix`, `modules/ai/validation-identities.nix` | Evaluation-time safety assertions. |
| Core services | `modules/nas/config/systemd-services.nix`, `application-services.nix` | Native upstream applications and appliance units. |
| Managed Services V2 | `modules/nas/config/managed-services.nix`, `managed-services-backup-resources.nix` | V3 desired-state seed/bootstrap, finite reconciliation, runtime projections, backup resources, and native integration. |
| Proxy/auth | `modules/nas/config/reverse-proxy.nix`, `internal/caddy-helpers.nix`, `services/nas_v2_caddy.py` | Caddy + Authentik trusted-header and request-time authorization boundary. |
| Storage | `modules/nas/config/storage-monitoring.nix`, `internal/zfs-tools.nix` | ZFS, snapshots, restore verification, replication, and Restic integration. |
| Observability | `modules/nas/config/observability.nix` | VictoriaMetrics, Telegraf, vmalert, NAS alert router, optional Grafana/ntfy. |
| Identity/capability policy | `modules/nas/internal/capability-registry.nix`, corresponding schemas | Appliance identity capability/group contract; Managed Services V2 itself does not own users, groups, or assignments. |
| Command packaging | `modules/nas/internal/account-tools.nix` | Installs Python tools, finite V2 control aliases, portal assets, and Authentik blueprint. |
| Documentation/UI packaging | `modules/nas/internal/documentation-tools.nix` | Builds mdBook references and the Cockpit plugin. |

`modules/nas/internal/default.nix` merges internal contexts with duplicate-name detection. New helpers should stay local unless multiple configuration modules consume them.

Managed Services V2 has one mutable desired-state authority: `/var/lib/nas-control/services.yaml`. `features.json` and `settings.json` are migration inputs only and must not become live runtime authority again.

## Python services

| Entry point/module | Responsibility | Main tests |
|---|---|---|
| `nas_setup.py` | First-run orchestration, guarded storage creation, runtime account commands | `test_setup.py` |
| `nas_setup_config.py` | Setup schema, normalization, and secure secret-file input | `test_setup.py` |
| `nas_identity_sync.py` | Authentik and Syncthing I/O/reconciliation entry point | `test_identity_sync.py` |
| `nas_identity_model.py` | Pure identity, account-plan, and Syncthing desired-state model | `test_identity_sync.py` |
| `nas_cockpit_api.py` | Fixed privileged action allow-list for Cockpit | `test_cockpit_api.py` |
| `nas_operation_lock.py` | Shared cross-process conflict classes and reconnect-safe active-operation metadata | `test_operation_lock.py`, `test_cockpit_api.py` |
| `nas_operation_journal.py` | Durable resumable-operation phases and manual-recovery stop semantics | `test_setup.py`, `test_identity_sync.py` |
| `nas_state.py` | Signed profile-aware state export, drift, validation, rollback, and restore | `test_state.py`, `test_v2_state_authority.py` |
| `nas_doctor.py` | Unified appliance diagnostics and V2 desired/effective drift detection | `test_doctor_migrations.py` |
| `nas_syncthing_devices.py` | Narrow user-attribute parser/validator | `test_syncthing_devices.py` |
| `nas_common.py` | Shared appliance parsing and policy helpers | `test_common.py`, `test_capability_registry.py` |
| `nas_alert_router.py` | Bounded vmalert notification routing, status, deduplication, and optional ntfy delivery | `test_alert_router.py` |
| `nas_logging.py` | Redacted bounded JSON operation records for journald | `test_logging.py` |
| `nas_migrate_state.py` | One-time migration compatibility for legacy state authorities | `test_doctor_migrations.py` |
| `nas_v2_spec.py` | YAML 1.2 parsing, V3 schema validation, normalization, semantic validation, and effective-state compilation | `test_v2_spec.py` |
| `nas_v2_plan.py`, `nas_v2_apply.py` | Deterministic plan generation and finite transactional apply orchestration | `test_v2_plan_apply.py` |
| `nas_v2_cli.py` | Administrative compile/plan/apply CLI | `test_v2_cli.py` |
| `nas_v2_control.py`, `nas_v2_editor.py` | Finite status/document/edit/reconcile API and comment-preserving atomic edits | `test_feature_control.py`, `test_v2_editor.py` |
| `nas_v2_systemd.py` | Unified systemd lowering for cross-runtime lifecycle, dependencies, jobs, readiness, attachments, leases, and idle timers | `test_v2_systemd.py` |
| `nas_v2_quadlet.py` | Direct OCI/Quadlet projection | `test_v2_quadlet.py` |
| `nas_v2_compose.py` | Compose override projection for V2-owned cross-cutting policy | `test_v2_compose.py`, `test_v2_compose_systemd.py` |
| `nas_v2_libvirt.py` | Libvirt/QEMU projection and explicit passthrough policy | `test_v2_libvirt.py` |
| `nas_v2_session.py`, `nas_v2_session_projection.py` | Finite transient-session launch and descriptor/resource/network projection | `test_v2_session.py`, `test_v2_session_projection.py` |
| `nas_v2_accelerator.py` | Generic accelerator resolution for device nodes, CDI, Compose targets, and VM passthrough | `test_v2_accelerator.py` |
| `nas_v2_podman_network.py`, `nas_v2_firewalld.py` | Native isolated Podman network and firewalld policy projection | `test_v2_podman_network.py`, `test_v2_firewalld.py` |
| `nas_v2_authentik.py` | Ensures stable `application.<service>.<capability>` objects without owning assignments | `test_v2_authentik.py` |
| `nas_v2_caddy.py`, `nas_v2_wake.py` | Request-time routing/auth projection and authorization-free post-auth wake plumbing | `test_v2_caddy.py`, `test_v2_wake.py` |
| `nas_v2_backup.py`, `nas_v2_backup_runtime.py`, `nas_v2_native_dump.py` | Resource-oriented backup inventory and finite preparation/cleanup jobs | `test_v2_backup.py`, `test_v2_backup_runtime.py`, `test_v2_native_dump.py` |

The installed legacy command name `nas-feature-control` is only an executable alias to `nas_v2_control:main`; there is no `nas_feature_control.py` implementation. Do not restore the deleted gate/controller/reaper architecture to satisfy old tests or documentation.

Pure policy and schema helpers should contain no service-management side effects. Runtime adapters project normalized V3 state into native mechanisms and fail closed when a requested semantic cannot be represented.

## Front end

- `cockpit/src/index.jsx`: React 18 entry point and PatternFly stylesheet imports.
- `cockpit/src/app.jsx`: PatternFly page, forms, cards, status views, tables, and confirmation modals.
- `cockpit/src/api.js`: allowed Cockpit bridge invocations, including finite Managed Services document/status/edit calls and stdin-only secret delivery.
- `cockpit/src/view-model.js`: pure backend-to-view conversion and visibility policy.
- `cockpit/src/app.scss`: NAS-specific layout only; PatternFly owns component styling.
- `cockpit/build.js`: Starter Kit style esbuild/Sass source-to-package build and source-hash stale-output check.
- `cockpit/dist/`: generated React/PatternFly package payload installed by Nix; never edit it directly.
- `web/portal/index.html`: Caddy template, not an application service.

Pure Cockpit API and view-model behavior has direct Node coverage. JSX component composition is checked structurally and through the built browser package in CI.

## Validation

- `scripts/preflight.sh`: small validation orchestrator.
- `scripts/validate-structure.py`: generic repository shape/version checks.
- `scripts/validate-repository-data.py`: JSON/TOML/schema checks.
- `tests/test_contract_*.py`: cross-file architecture and security contracts.
- `tests/test_v2_*.py`: V3 compiler, adapter, reconciliation, resource, session, and authority contracts.
- `scripts/qemu-test.sh`: native NixOS tests and full ISO install/reboot test.
