# Control-plane services

These modules back installed appliance commands and finite reconciliation helpers. Managed Services V2 is compiler-driven: request authorization belongs to Caddy + Authentik and service lifecycle is projected into native systemd/Podman/libvirt mechanisms rather than owned by a resident controller. There is no supported V1 feature-state or managed-service compatibility layer.

| Module | Responsibility |
|---|---|
| `nas_common.py` | Side-effect-free shared parsing and V2 application-capability helpers |
| `nas_setup.py` | First-start and guarded runtime account/V2 service orchestration |
| `nas_setup_config.py` | Setup schema and secure secret-input validation |
| `nas_identity_sync.py` | Authentik API operations and reserved Syncthing reconciliation |
| `nas_identity_model.py` | Pure identity/application-capability/account-plan models |
| `nas_cockpit_api.py` | Fixed privileged Cockpit action allow-list |
| `nas_operation_lock.py` | Cross-process conflict reservations |
| `nas_operation_journal.py` | Resumable workflow journal/manual-recovery boundary |
| `nas_state.py` | Signed state export, validation, diff, and restore |
| `nas_doctor.py` | Unified appliance diagnostics, including V2 desired/effective drift |
| `nas_alert_router.py` | Bounded vmalert routing/deduplication and ntfy delivery |
| `nas_syncthing_devices.py` | Narrow user-device declaration validation |
| `nas_v2_spec.py` | YAML 1.2 parsing, schema validation, normalization, semantic validation, and effective-state compilation |
| `nas_v2_plan.py` | Deterministic reconciliation plan generation |
| `nas_v2_apply.py` | Finite compile/apply orchestration and projection staging |
| `nas_v2_cli.py` | Administrative compile/plan/apply command surface |
| `nas_v2_control.py` | Finite status/document/edit/reconcile surface used by Cockpit and operators |
| `nas_v2_editor.py` | Comment-preserving atomic `services.yaml` editing |
| `nas_v2_systemd.py` | Unified systemd projection for cross-runtime lifecycle, jobs, readiness, dependencies, and on-demand lease/idle units |
| `nas_v2_quadlet.py` | Direct OCI/Quadlet projection |
| `nas_v2_compose.py` | Compose override projection for V2-owned cross-cutting policy |
| `nas_v2_libvirt.py` | Libvirt/QEMU runtime projection |
| `nas_v2_session.py` | Finite transient-session launcher |
| `nas_v2_session_projection.py` | Session descriptors, lifecycle targets, resource/device/network lowering |
| `nas_v2_podman_network.py` | Native Podman isolated-network projection |
| `nas_v2_firewalld.py` | Firewalld policy projection for compiled network intent |
| `nas_v2_authentik.py` | Ensures stable V2 application/capability objects without owning assignments |
| `nas_v2_caddy.py` | Caddy routing and Authentik request-time authorization projection |
| `nas_v2_wake.py` | Authorization-free socket-activated wake plumbing after Caddy authorization |
| `nas_v2_backup.py` | Resource-oriented backup inventory compilation |
| `nas_v2_backup_runtime.py` | Finite backup preparation/cleanup from compiled inventory |
| `nas_v2_native_dump.py` | Generic synchronous native-dump job preparation |

## Dependency direction

```text
pure/common + V2 specification helpers
        ↑
compiler and runtime adapters
        ↑
finite command/reconciliation surfaces
        ↑
Nix wrappers and native systemd/Podman/libvirt units
```

Do not reintroduce a resident Managed Services controller, request-time authorization server, idle reaper, mutable V2 identity database, V1 compatibility authority, or application-name branches in generic adapters. Do not import one command entry point from another merely to reuse implementation details; move genuinely shared, side-effect-free behavior into a narrowly named helper module. Preserve test injection points when splitting large files.
