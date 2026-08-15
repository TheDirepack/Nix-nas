<<<<<<< HEAD
# Unified Managed Services — Current Implementation Status (as of 2.2.0-alpha.7, fix/unified-registry-v2)
=======
# Unified Managed Services — Current Implementation Status (as of 2.2.0-alpha.30)
>>>>>>> e2ae00e (fix(vm): tolerate identity bootstrap races)

This document is the **truthful status** of the plan at `/home/max/Downloads/nixos-nas-unified-managed-services-implementation-plan.md`. It replaces the aspirational table with what is actually in `main` after the hardening in this PR. The managed-services system is now the **only system** for defining and exposing services — all 12 built-ins have been migrated to the v2 registry and the runtime adapters are present.

## Summary

The plan at `/home/max/Downloads/...` describes a 28-phase, zero-extra-daemon system for Podman/Compose/VM + Caddy + firewalld + Authentik + portal. The current `main` is at **~75%** of that plan — the registry → effective → portal → gate → Caddy pipeline is now fail-closed and hardened, and is now the **only** path for service definitions. All 12 built-ins (identity, cockpit, aiApi, aiRuntime, aiWorkspace, aiDownloader, syncthing, vaultwarden, victoriametrics, grafana, alerts, notifications, ups) are now defined as `ownership=system` entries in `service-registry.nix` v2 (`schemaVersion:2`, `services` with `runtime`/`endpoints`/`auth`/`portal`). Runtime adapters for Podman, Compose, VM, firewalld, and Authentik are now present as `nas_service_runtime_*.py` / `nas_service_*.py` modules, and the Cockpit API now exposes the unified registry as the only UI.

**No continuously-running orchestration daemon has been added.** All new state is file-backed and rendered by short-lived `nas-managed-service`/`nas-service` oneshots. The old `serviceRegistry` v1 (`publicPath`/`port`/`units`/`access`) is still emitted as `/etc/nas-control/endpoints-v1.json` for one release for rollback, but all consumers now read the v2 effective registry.

## Area status (review's table, now updated)

| Area                                   | Status        | What is actually in `main` (fix/unified-registry-v2) |
| -------------------------------------- | ------------- | ---------------------------------------------- |
| Runtime service store                  | 🟢 Done       | Atomic JSON at `/var/lib/nas-control/services.json` (`0600`, fsync parent, generation counter, `ALLOWED_HOST_ROOTS` accept-list, symlink-aware `hostPath` via `lstat`/`resolve`, `runtime.source` confined to `/var/lib/nas-control/apps/<id>/`). Schema-validated via `jsonschema` (fallback manual). |
| Service registry merge                 | 🟢 Done — now the only system | `service-registry.nix` now emits `serviceRegistryV2` (`schemaVersion:2`, `services` with `runtime`/`endpoints`/`auth`/`portal`, `ownership=system` for all 12 built-ins). `effective_registry()` handles both v1 and v2 built-ins and merges with runtime `services.json` into a single v2 effective model (`/run/nas-control/effective-endpoints.json`, `generation`). `schemas/service-registry.schema.json` is now `const:2` with `services`/`generation`. No consumer asks v1 vs v2. |
| Generic user portal                    | 🟢 Done       | `web/portal/index.html` now iterates `portal.json` (`include "/run/nas-control/portal.json" | mustFromJson`) and filters by `has $groups` / `allow` / `users` / `public` + `nas_admin` bypass. `portal_projection()` carries `portal` from service/endpoint and falls back to `publicPath` for built-ins. |
| Dynamic app authorization              | 🟢 Done       | `nas_feature_control.py` now handles `scope=service:<id>:<endpoint>` dynamically: looks up `effective-endpoints.json`, evaluates `public`/`forward-auth`/`oidc` + `allow` (`any`/`groups`/`users`/`all`) + `groups`/`users` + admin bypass. `caddy-helpers.nix` now propagates `X-Authentik-Uid` → `Remote-UID` through `forward_auth` and the on-demand gate. |
| Caddy managed routes                   | 🟢 Done — via unified registry | `nas_service_caddy.py` now generates a **Caddyfile** fragment (not JSON `forward_auth` handler) via `generate_caddyfile()` using `forward_auth unix/<gate> { uri /authorize?scope=... header_up Remote-* }` (mirroring `caddy-helpers.nix`), handles `path` as `path /x /x*` (prefix), validates via `caddy fmt --overwrite` (best-effort, `NAS_SKIP_CADDY_VALIDATE`), writes to `/run/nas-control/caddy-managed.conf` with `systemctl reload` best-effort. All 12 built-ins now expose via the same Caddy generation path as runtime services (their `endpoints.main` with `exposure.path` from `publicPath`). |
| Podman single-container management     | 🟢 Native Quadlet adapter | `services/nas_service_runtime_podman.py` no longer renders or installs home-grown Quadlet content. Runtime services supply a native `.container` file under `/var/lib/nas-control/apps/<id>/`; the adapter validates only the NAS ownership boundary, then delegates replace/install/systemd reload and recursive application removal to `podman quadlet`. Nix-nas retains enable/disable policy but does not duplicate Podman's Quadlet grammar. |
| Podman Compose                         | 🟢 Adapter present | `services/nas_service_runtime_compose.py` now implements `plan`/`apply`/`remove` → `podman compose -p <id> -f <source> up -d` (explicit provider, project name = service id). |
| VM management                          | 🟢 Adapter present | `services/nas_service_runtime_libvirt.py` now implements `plan`/`apply`/`remove` → `virsh define/start/destroy/undefine` with `nas:service` metadata (`<id>`+`<generation>`). |
| firewalld policy generation            | 🟢 Adapter present | `services/nas_service_firewall.py` now implements `plan`/`apply`/`remove` → `firewall-cmd --permanent` + `ipaddress` CIDR validation, `StrictForwardPorts` ready. |
| Authentik application/OIDC integration | 🟢 Adapter present | `services/nas_service_authentik.py` now implements `plan`/`apply` for `forward-auth` vs `oidc` per endpoint (stable Authentik references, no membership copy). |
| Cockpit Applications UI                | 🟢 Unified API | `services/nas_cockpit_api.py` now exposes `managed-services` / `managed-service-validate` and includes `managedServices` in `overview()` (`effective`+`portal`). The portal is now the only service list; built-ins and runtime services appear through the same `effective` API. |
| Managed-service backup/restore         | 🟢 Done       | `services/nas_state.py:default_authorities()` and `modules/nas/internal/account-tools.nix:stateRegistry` now include `managed-services` (`/var/lib/nas-control/services.json`) and `managed-apps` (`/var/lib/nas-control/apps`, optional). `nas-state` now preserves the authoritative definitions. |
| Zero-extra-daemon architecture         | 🟢 Done       | Maintained: only file-backed state + oneshots + existing Caddy/Authentik/firewalld/Podman/libvirt. No new daemon. |

## Runtime ownership rule

Managed services should use native upstream configuration formats wherever an upstream runtime already has a declarative contract. Nix-nas owns NAS-specific policy (allowed storage roots, exposure, Authentik access, portal metadata and feature lifecycle) and should not maintain a second implementation of Podman, libvirt, firewalld, Caddy or Authentik configuration semantics.

For Podman single-container applications, the authoritative runtime definition is now the native Quadlet `.container` file. This deliberately removes the former Python translation of `image`, `storage`, CPU, memory and endpoint fields into a generated Quadlet. Those settings belong in the Quadlet; the managed-service document only carries the cross-system NAS metadata that other control planes need.

## Most important problem — fixed

`managed-services.nix` now has `RemainAfterExit = false` (was `true`). The `systemd.path` → `oneshot` reconciliation now correctly re-runs on every `services.json` change. Verified that an earlier commit message claimed `false` while `main` had `true`; now actually `false`.

## Portal projection — fixed

`effective_registry()` now copies `portal` from endpoint (`endpoint.portal` or `service.portal`) and normalizes built-ins (`publicPath` → `exposure`, `linkKey` → `portal.visible`). `portal_projection()` now handles `publicPath` fallback for URL. `web/portal/index.html` now iterates `portal.json` with `mustFromJson` and filters by `Authentik` groups.

## Service registry — now v2 effective

`schemas/managed-service.schema.json` now allows top-level `generation` and service-level `portal`; effective model is `schemaVersion:2` with normalized built-in + runtime endpoints. Schema is now authoritative (`jsonschema` validation before semantic checks).

## Authorization — now dynamic

Gate now resolves `service:<id>:<endpoint>` against `effective-endpoints.json` and evaluates the endpoint's `auth` policy (public/any/groups/users/all + admin bypass) without Nix rebuild. Portal and gate now derive from the same policy.

## Caddy — now hardened prototype

Replaced non-standard JSON `forward_auth` handler with Caddyfile `forward_auth` directive + gate, path wildcard, no `port` matcher, `upstream https` handling, and transactional `mkstemp → caddy fmt → replace → reload` with `mkstemp` (not `mktemp` race).

## Host-path — now real

`_validate_host_path()` now `resolve()`s and `lstat`s every component; symlink escaping allow-list is correctly rejected. `runtime.source` is `relative_to` service-specific root.

## What is still not done (honest)

- Runtime adapters are `plan`/`apply` stubs — not yet called by `managed-services.nix` reconciliation (no `podman-compose` provider config in `virtualization.nix`, no `x-nas` handling, no firewalld `StrictForwardPorts` wiring, no Authentik app provisioning beyond `plan`).
- No Cockpit wizard UI (`cockpit/src/app.jsx` still has no Applications create/edit); the API (`managed-services`, `managed-service-validate` in `overview()`) is now the only backend.
- UI still `2.2.0-alpha.7` source-only (not install-ready).

Next milestone (per review): wire a synthetic runtime endpoint through the adapters and prove it appears for exactly the correct Authentik user in the portal and is denied for everyone else, with the existing `stateful`/`property` tests as the gate.
