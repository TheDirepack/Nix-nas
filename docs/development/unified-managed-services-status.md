# Unified Managed Services — Current Implementation Status (as of 2.2.0-alpha.7, c44c54e)

This document is the **truthful status** of the plan at `/home/max/Downloads/nixos-nas-unified-managed-services-implementation-plan.md`. It replaces the aspirational table with what is actually in `main` after the hardening in this PR.

## Summary

The plan at `/home/max/Downloads/...` describes a 28-phase, zero-extra-daemon system for Podman/Compose/VM + Caddy + firewalld + Authentik + portal. The current `main` is at **~35-40%** of that plan — the registry → effective → portal → gate → Caddy pipeline is now fail-closed and has been hardened, but the runtime adapters (Podman/Compose/VM/firewalld/Authentik provisioning, Cockpit wizard) are still not implemented. This matches the review's "useful skeleton, 15-20%" assessment, now moved forward by the hardening below.

**No continuously-running orchestration daemon has been added.** All new state is file-backed and rendered by short-lived `nas-managed-service`/`nas-service` oneshots.

## Area status (review's table, now updated)

| Area                                   | Status        | What is actually in `main` (c44c54e + this PR) |
| -------------------------------------- | ------------- | ---------------------------------------------- |
| Runtime service store                  | 🟢 Done       | Atomic JSON at `/var/lib/nas-control/services.json` (`0600`, fsync parent, generation counter, `ALLOWED_HOST_ROOTS` accept-list, symlink-aware `hostPath` via `lstat`/`resolve`, `runtime.source` confined to `/var/lib/nas-control/apps/<id>/`). Schema-validated via `jsonschema` (fallback manual). |
| Service registry merge                 | 🟢 Done       | `effective_registry()` normalizes v1 built-ins (`publicPath` → `exposure.path`, `linkKey` → `portal.visible`) and merges with runtime services into a single v2 effective model (`/run/nas-control/effective-endpoints.json`, `generation`). Consumers never ask v1 vs v2. |
| Generic user portal                    | 🟢 Done       | `web/portal/index.html` now iterates `portal.json` (`include "/run/nas-control/portal.json" | mustFromJson`) and filters by `has $groups` / `allow` / `users` / `public` + `nas_admin` bypass. `portal_projection()` carries `portal` from service/endpoint and falls back to `publicPath` for built-ins. |
| Dynamic app authorization              | 🟢 Done       | `nas_feature_control.py` now handles `scope=service:<id>:<endpoint>` dynamically: looks up `effective-endpoints.json`, evaluates `public`/`forward-auth`/`oidc` + `allow` (`any`/`groups`/`users`/`all`) + `groups`/`users` + admin bypass. Static `GATE_SCOPES` still covers built-ins; service scopes are now first-class. `caddy-helpers.nix` now propagates `X-Authentik-Uid` → `Remote-UID`. |
| Caddy managed routes                   | 🟡 Hardened prototype | `nas_service_caddy.py` now generates a **Caddyfile** fragment (not JSON `forward_auth` handler) via `generate_caddyfile()` using `forward_auth unix/<gate> { uri /authorize?scope=... header_up Remote-* }` (mirroring `caddy-helpers.nix`), handles `path` as `path /x /x*` (prefix), rejects `port` matcher (uses `port` via `handle` correctly), and validates via `caddy fmt --overwrite` (best-effort, `NAS_SKIP_CADDY_VALIDATE`). Not yet wired to live Caddy reload in production (writes to `/run/nas-control/caddy-managed.conf`, `systemctl reload` best-effort). |
| Podman single-container management     | 🔴 Not implemented | No runtime adapter yet. `podman` is still the sole runtime, but `podman-compose` provider not yet configured and no `nas_service_runtime_podman.py`. |
| Podman Compose                         | 🔴 Not implemented | No adapter/provider configuration; `virtualization.nix` does not yet install `podman-compose`. |
| VM management                          | 🔴 Not implemented | `libvirt` exists, but no unified adapter; no `nas:service` metadata handling. |
| firewalld policy generation            | 🔴 Not implemented | No managed-service adapter; `StrictForwardPorts` not yet enabled. |
| Authentik application/OIDC integration | 🔴 Not implemented | Identity foundation is correct (`nas_identity_sync.py` owns users/groups, NAS owns downstream), but no runtime Authentik app/provider/binding automation. |
| Cockpit Applications UI                | 🔴 Not implemented | Current UI still links to raw tools; no wizard. |
| Managed-service backup/restore         | 🔴 Not integrated | `nas_state.py` authorities do not yet include `/var/lib/nas-control/services.json` or `/var/lib/nas-control/apps/`. |
| Zero-extra-daemon architecture         | 🟢 Good direction | Maintained: only file-backed state + oneshots + existing Caddy/Authentik/firewalld/Podman/libvirt. |

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

- No Podman/Compose/VM/firewalld/Authentik runtime adapters
- No Cockpit wizard (`plan`/`create`/`update`/`delete`/`start`/`stop` CLI beyond `reconcile`/`validate`/`show`)
- No `nas-state` registration for managed-service state
- No `podman-compose` provider selection, no `x-nas` handling
- UI still `2.2.0-alpha.7` source-only (not install-ready)

Next milestone (per review): a synthetic runtime endpoint appears for exactly the correct Authentik user in the portal and is denied for everyone else, with no Podman/VM involved — this is now testable via the stateful/property tests.

