# Hardcoding Audit — V2 Seed Authority

Date: 2026-05-15
Scope: `modules/nas/**/*.nix` + `modules/ai/**/*.nix` + `services/nas_*.py` / `services/nas_v2_*.py` + `cockpit/src/**/*`
Exempt core: Authentik, Cockpit, Caddy platform substrate (may remain hardcoded), but Caddy still contains a Syncthing-specific branch at `reverse-proxy.nix:79` which is not exempt and should be V2-driven.

## Where V2 YAMLs live

Single mutable file authority: `/var/lib/nas-control/services.yaml` → `${zfsRoot}/nas-control/services.yaml`.

- Nix-generated baseline `managed-services-seed-v2.nix` → `${store}/managed-services-seed-v2.yaml` → installed once by `nas_v2_bootstrap.py --seed/--marker/--desired` (marker `/var/lib/nas-control/.managed-services-native-seed-v2`) when none existed; afterwards owner is the administrator (GUI/YAML, not Nix).
- Schema: `schemas/managed-services-v3.schema.json` (identical `spec/managed-services/managed-services-v3.schema.json`); examples `spec/managed-services/examples/*.yaml`.
- Code still merges a directory authority (`services/` multi-YAML) — transitional; Nix side seeds a file and warns against a directory.

Previously two split no-op modules (`managed-services-native-services.nix`, `managed-services-platform-routes.nix`) re-defined the same catalog with no output and no routes. Deleted in this change; `managed-services-seed-v2.nix` is now the sole catalog authority and `managed-services-helpers.nix` the shared helper set.

## Findings and fixes

### 1. App ports were a second hardcoded authority

`base.nix:36-37` (`syncthingGuiPort = 8384`, `vaultwardenPort = 8222`) and literal listeners `22000`/`21027`/`3493` duplicated across Nix and Python (`nas_identity_sync.py:8384`, `nas_v2_network.py:9092`, `nas_state.py` quiesce, etc.). The V2 schema already carries `httpTarget.port` and `portListener` — hardcoding elsewhere was a second authority.

Fix: `managed-services-helpers.nix` now defines the V2 application catalog ports (`syncthingGuiPort`, `syncthingSyncPort`, `syncthingDiscoveryPort`, `vaultwardenPort`, `nutUpsdPort = cfg.power.ups.web.upsdPort`) as the single Nix authority. `managed-services-seed-v2.nix` consumes those helpers for `listeners` (`syncthingSyncPort` etc., `nutUpsdPort`) and `httpTarget` routes. `base.nix` re-exports them for native$config consumers (`application-services.nix`, `systemd-services.nix`, `caddy-helpers.nix`, `loopbackServicePorts`). `host-platform.nix` NUT `upsd.listen 3493` → `cfg.power.ups.web.upsdPort`; `validation.nix` tftp-vs-syncthing conflict now imports `helpers` instead of `[21027 22000]` literals. Python `nas_identity_sync.SYNCTHING_URL` now prefers `NAS_SYNCTHING_URL` → V2 `effective.json` syncthing route port → `8384` fallback; `nas_v2_network._REMOTE_ADMIN_PORTS` cockpit `9092` now derives from `NAS_V2_COCKPIT_PORT` with fallback (core substrate, not app config).

### 2. Duplicate native catalog modules

`default.nix:28-29` imported both split seeds as no-ops; `documentation-tools.nix:178` and `validate-structure.py:29-30` required them; six contract tests read `native-services` as a native-only catalog. Content was a strict subset of `seed-v2.nix`.

Fix: deleted both modules and their imports; `code-map.md` and `validate-structure.py` updated; tests re-pointed to `seed-v2.nix` (`test_v2_native_listeners`, `test_v2_platform_runtime_ownership`, `test_v2_vlan_and_direct_listeners`, `test_v2_reference.test_no_duplicate_route_catalogs` now asserts no `pathRoute [` outside `seed-v2.nix`/`helpers.nix`).

### 3. Python service/capability literals — fail-closed from V2

`nas_common:256` (`"copyparty","files"`) and `nas_identity_model:44` (`"syncthing","access"`) embedded V2 app ids and fell back to legacy groups when V2 was authoritative but did not define the service. Repro: effective with no `syncthing` service still authorized `application.syncthing.access`.

Fix: both now resolve `service`/`capability` from `NAS_V2_*` env and validate against `V2 effective.json` `derived.authorization`. When V2 is readable and non-empty but does not contain the requested service/capability, they return `None` and the caller denies (`return False`) — fail closed. Only when V2 is unreadable (pre-V2 caller, file missing) do they fall back to the historic literals.

### 4. Dynamic unit lists and VM dependency — V2-first

`nas_state:614` `export_quiesce_units()` previously checked `NAS_STATE_QUIESCE_UNITS_JSON` first (always set by `account-tools.nix:353`) and only fell back to V2 `derived.runtime` with an incorrect `if any(legacy in units)` gate that re-introduced all three legacy app units for a `demo.service` effective.

Fix: `export_quiesce_units()` now checks `V2 effective.json` first (`caddy`/`authentik` core + `derived.runtime` managed `ownerUnit`s), then `NAS_STATE_QUIESCE_UNITS_JSON`, then static tuple. The legacy-unit gate is removed. `account-tools.nix` still exports the var for non-V2 callers, but V2 now takes precedence. `nas_v2_systemd._vm_unit:613` derives `libvirt_unit` from `effective.services.virtualization.runtime.unit` with `libvirtd.service` fallback.

### 5. Remaining Python path/state-root literals

`nas_state` authorities, `nas_ai_config`, `nas_cockpit_api`, `nas_identity_sync` config dir defaults already honor `NAS_*` env with hardcoded fallbacks matching the Nix `zfsRoot`-derived paths. With the V2-effective fallbacks above plus env injection at the owning systemd units, the fallbacks are no longer authority. Caddy/secret substrate paths remain exempt.

### 6. Known remaining non-compliance (not yet moved to V2)

- AI control plane (`nas_ai_config.py:22`, `nas_cockpit_api.py:804`, `cockpit/src` AI editor) still owns llama-swap config outside V2; V2 only controls `ai-runtime`/`ai-workspace` lifecycle.
- Coding agent (`coding-agent.nix:113`, `nas_coding_agent.py:70`) still owns netns/veth/NAT/socat/heartbeat outside V2 session.
- Backup/state paths duplicated in `storage-monitoring.nix:168` (Restic) and `account-tools.nix:132` (state registry) vs `managed-services-seed-v2.nix` `storageResources`; AI paths are in Restic/state but not in V2 `storageResources`.
- Caddy `reverse-proxy.nix:79` still has a Syncthing-specific `application.syncthing.admin` branch and `caddy-helpers.nix:34` retains CopyParty/Vaultwarden helpers though V2 generates routes generically.
- Identity sync (`nas_identity_model:229`, `nas_identity_sync:575`) still hard-codes Syncthing policy, CopyParty share layout, and Syncthing API reconciliation beyond bare plumbing.
- Alert router `nas_alert_router.py:1` is a full custom daemon.
- Application ports remain centralized in `managed-services-helpers.nix:7` (single Nix authority) rather than in the mutable V2 object itself — the helpers are now the Nix-side catalog, not yet fully in `services.yaml`.

## Verification

- `test_v2_reference.test_cockpit_port_consistency` now validates `_remote_admin_ports` derivation via `NAS_V2_COCKPIT_PORT` (not a literal) and `base.nix:cockpitPort`.
- `nas_state.export_quiesce_units` with `effective={demo.service}` now returns `[authentik, auth-worker, caddy, demo.service]` (not legacy copyparty/syncthing/vaultwarden).
- `nas_common.account_has_personal_share` / `nas_identity_model.personal_sync` with `effective={}` or missing service now correctly deny.
- Full suite: 723 passing, 6 skipped, 1 stale-port test now fixed; 3 socket sandbox failures pass with socket permission.
- `scripts/validate-structure.py` — `REQUIRED_FILES` no longer lists the deleted split seeds; `cockpit/dist` rebuilt and `VERSION`/`README`/`flake` metadata synced.
