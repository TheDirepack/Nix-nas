# Hardcoding Audit — V2 Seed Authority

Date: 2026-05-13
Scope: `modules/nas/**/*.nix` + `services/nas_*.py` / `services/nas_v2_*.py`
Exempt core: Authentik, Cockpit, Caddy (platform substrate — may remain hardcoded)

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

### 3. Python service/capability literals

`nas_common:256` (`"copyparty","files"`) and `nas_identity_model:44` (`"syncthing","access"`) embedded V2 app ids.

Fix: both now resolve `service`/`capability` from `NAS_V2_*` env (injected by Nix) and validate against `V2 effective.json` `derived.authorization[service].capabilities` before falling back to the historic literals.

### 4. Dynamic unit lists and VM dependency

`nas_state:624` quiesce tuple (`copyparty/syncthing/vaultwarden` + core), `nas_cockpit_api:1020` overview units, `nas_v2_systemd:613` `Requires=libvirtd.service`.

Fix: `export_quiesce_units()` now tries `NAS_STATE_QUIESCE_UNITS_JSON` → `V2 effective.json` `derived.runtime` managed owner units plus core platform units, falling back to the static tuple; `nas_v2_systemd._vm_unit` derives `libvirt_unit` from `effective.services.virtualization.runtime.unit` with `libvirtd.service` fallback.

### 5. Remaining Python path/state-root literals

`nas_state` authorities, `nas_ai_config`, `nas_cockpit_api`, `nas_identity_sync` config dir defaults already honor `NAS_*` env with hardcoded fallbacks matching the Nix `zfsRoot`-derived paths. With the V2-effective fallbacks above plus env injection at the owning systemd units, the fallbacks are no longer authority. Caddy/secret substrate paths remain exempt.

## Verification

- `PYTHONPATH=tests:services python -m unittest tests.test_v2_native_listeners tests.test_v2_vlan_and_direct_listeners tests.test_v2_platform_runtime_ownership tests.test_v2_reference tests.test_v2_seed_once_contract tests.test_contract_operations tests.test_alpha18_hardening` — 49 OK
- `test_v2*` suite (partial above, 43 files) — all PASS
- `scripts/validate-structure.py` — `REQUIRED_FILES` no longer lists the deleted split seeds
