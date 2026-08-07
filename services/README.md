# Control-plane services

These modules back installed appliance commands. Keep public command names and externally visible CLI behavior stable unless a migration is deliberate and documented.

| Module | Responsibility |
|---|---|
| `nas_common.py` | Side-effect-free shared parsing/policy helpers |
| `nas_setup.py` | First-start and guarded runtime account orchestration |
| `nas_setup_config.py` | Setup schema and secure secret-input validation |
| `nas_identity_sync.py` | Authentik API operations and reserved Syncthing reconciliation |
| `nas_identity_model.py` | Pure identity/capability/account-plan models |
| `nas_feature_control.py` | Runtime feature lifecycle and Unix-socket authorization |
| `nas_feature_model.py` | Pure feature catalog/dependency policy |
| `nas_cockpit_api.py` | Fixed privileged Cockpit action allow-list |
| `nas_operation_lock.py` | Cross-process conflict reservations |
| `nas_operation_journal.py` | Resumable workflow journal/manual-recovery boundary |
| `nas_state.py` | Signed state export, validation, diff, and restore |
| `nas_alert_router.py` | Bounded vmalert routing/deduplication and ntfy delivery |
| `nas_syncthing_devices.py` | Narrow user-device declaration validation |

## Dependency direction

```text
pure/common helpers
        ↑
config and model modules
        ↑
command/orchestration modules
        ↑
Nix wrappers and systemd units
```

Do not import one command entry point from another just to reuse implementation details. Move genuinely shared, side-effect-free behavior into `nas_common.py` or a narrowly named model/helper module. Preserve test injection points when splitting large files.
