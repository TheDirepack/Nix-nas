# Code map

## NixOS module

| Area | Primary files | Notes |
|---|---|---|
| Options | `modules/nas/options/*.nix`, `modules/ai/options.nix` | Public configuration contract. |
| Validation | `modules/nas/config/validation.nix`, `modules/ai/validation-identities.nix` | Evaluation-time safety assertions. |
| Core services | `modules/nas/config/systemd-services.nix`, `application-services.nix` | Units and upstream applications. |
| Proxy/auth | `modules/nas/config/reverse-proxy.nix`, `internal/caddy-helpers.nix` | Trusted-header boundary and routes. |
| Storage | `modules/nas/config/storage-monitoring.nix`, `internal/zfs-tools.nix` | ZFS, snapshots, restore, replication, Restic. |
| Observability | `modules/nas/config/observability.nix` | VictoriaMetrics, Telegraf, vmalert, NAS alert router, optional Grafana/ntfy. |
| Feature and authorization policy | `modules/nas/internal/feature-catalog.nix`, `internal/capability-registry.nix`, corresponding schemas | Declarative feature graph and fail-closed capability/group contract. |
| Command packaging | `modules/nas/internal/account-tools.nix` | Installs Python tools, wrappers, portal assets, and Authentik blueprint. |
| Documentation/UI packaging | `modules/nas/internal/documentation-tools.nix` | Builds mdBook references and the Cockpit plugin. |

`modules/nas/internal/default.nix` merges internal contexts with duplicate-name detection. New helpers should stay local unless multiple configuration modules consume them.

## Python services

| Entry point | Responsibility | Main tests |
|---|---|---|
| `nas_setup.py` | First-run orchestration, guarded storage creation, runtime account commands | `test_setup.py` |
| `nas_setup_config.py` | Setup schema, normalization, and secure secret-file input | `test_setup.py` |
| `nas_identity_sync.py` | Authentik and Syncthing I/O/reconciliation entry point | `test_identity_sync.py` |
| `nas_identity_model.py` | Pure identity, account-plan, and Syncthing desired-state model | `test_identity_sync.py` |
| `nas_feature_control.py` | Feature lifecycle, systemd operations, wake/reap, authorization gate | `test_feature_control.py` |
| `nas_feature_model.py` | Pure catalog normalization, graph policy, and state migrations | `test_feature_control.py` |
| `nas_cockpit_api.py` | Fixed privileged action allow-list for Cockpit | `test_cockpit_api.py` |
| `nas_operation_lock.py` | Shared cross-process conflict classes and reconnect-safe active-operation metadata | `test_operation_lock.py`, `test_cockpit_api.py` |
| `nas_operation_journal.py` | Durable resumable-operation phases and manual-recovery stop semantics | `test_setup.py`, `test_identity_sync.py` |
| `nas_state.py` | Signed profile-aware state export, drift, validation, rollback, and restore | `test_state.py` |
| `nas_syncthing_devices.py` | Narrow user-attribute parser/validator | `test_syncthing_devices.py` |
| `nas_common.py` | Shared generated capability policy, feature-state helpers, subprocess parsing | `test_common.py`, `test_capability_registry.py` |
| `nas_alert_router.py` | Bounded vmalert notification routing, status, deduplication, and optional ntfy delivery | `test_alert_router.py` |
| `nas_logging.py` | Redacted bounded JSON operation records for journald | `test_logging.py` |

The installed CLI names remain stable. Pure policy and schema modules contain no subprocess, filesystem-mutation, or service-management code.

## Front end

- `cockpit/src/index.jsx`: React 18 entry point and PatternFly stylesheet imports.
- `cockpit/src/app.jsx`: PatternFly page, forms, cards, status views, tables, and confirmation modals.
- `cockpit/src/api.js`: only allowed Cockpit bridge invocation, including stdin-only first-run and unlock secret delivery.
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
- `scripts/qemu-test.sh`: native NixOS tests and full ISO install/reboot test.
