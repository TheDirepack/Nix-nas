# NixOS NAS Unified Managed Services — Implementation Plan v2 (Improved)

**Baseline:** Nix OS NAS 2.2.0-alpha.6 (fixes for 2.2.5 review: Pi 0.75.4 compat, loopback-only coding sandbox, hyphen-only provider IDs, atomic provider credential+config transaction, reserved-env deny-list, `nas-ai-coding.slice/target`, state registry for `/var/lib/nas-code-agent`)  
**Document type:** Architecture + implementation + qualification plan  
**Status:** Draft for Alpha.7 planning — replaces v1 at `nixos-nas-unified-managed-services-implementation-plan.md`  
**Versioning note:** Plan is documentation-only; any code based on it bumps `VERSION`.

---

## 0. What v2 Fixes vs v1

| Gap in v1 | v2 change | Why |
|---|---|---|
| No explicit transaction for multi-authority secrets/config | Add **one-transaction** pattern from Alpha.6 provider fix: `NAS_SKIP_LLAMA_SWAP_RESTART` + single restart + rollback of KeePass/env/config. Apply same to Caddy/firewalld/Authentik/Quadlet. | Prevents C-04 class “new credential → old endpoint” across all managed services. |
| Portal and gate described separately, no shared policy test | Add **portal ↔ gate parity** acceptance: `effective-endpoints.json` and `portal.json` rendered from same projection; fuzz `Remote-*` vs `X-Authentik-*`. | Closes H-08 / portal visibility ≠ security. |
| Storage and network described but no protected-path deny-list | Add explicit `PROTECTED_HOST_PATHS` (`/`, `/etc`, `/run/nas-secrets`, `/var/lib/nas-llama-swap`, `/var/lib/nas-control`) and `STRICT_PORTS` validation before generate. | Prevents container `ports:`/`volumes:` bypassing NAS policy. |
| SQLite vs JSON left ambiguous | Make **SQLite the default** for Phase 1, with `services.db` + `effective.json` projection; JSON only as export format. | VM tests prove SQLite gives crash-safe migrations without resident daemon (v1 already argued this). |
| No effort/risk tuning for review feedback | Add **effort (S/M/L) + risk** per phase and a “defer if memory >5 MiB idle” gate. | Keeps management layer at “config data only” as required. |
| VM harness treated as external | Document **root vs version test split**: host `pytest` needs `/var/lib` mocks, VM `test/qemu/harness.sh` is authoritative for `/var/lib`/`/run` paths. v2 mandates `nix-shell /tmp/shell.nix` with `python.withPackages [pyyaml pytest]` for host parity. | Explains Alpha.6 VM re-run: 420/426 passed after `VERSION`/`README`/`flake.nix`/`cockpit/package.json` sync and `docs/development/artifact-naming.md` fix; remaining 1 failure is `shellcheck -S warning` on pre-existing `live-validation.sh` SC2016. |

---

## 1. Objective (unchanged, tightened)

One Cockpit **Applications** workflow creates/updates/deletes **any** workload (Podman `Quadlet`, `podman-compose`, `libvirt` VM, built-in Nix service, raw `HTTP`/`TCP`/`UDP` endpoint) with one form for: source/runtime, start policy, CPU/RAM/GPU, env/secrets, mounts (ZFS), ports, egress/LAN/app-to-app, Caddy `path`/`hostname`/`port`, public vs Authentik, portal visibility, backups, health, logs, updates.

**Memory contract:** No new resident daemon. Idle RSS delta = growth of `Caddy`/`firewalld`/`Authentik` rule data only — measured by `ps -o rss` before/after on identical `nas-ci-ready` VM.

---

## 2. Non-Negotiable Rules (v1 §2 + hardening)

* **Podman only** (`Quadlet` + `podman-compose` with `provider = "podman-compose"`). No Docker/Incus/K8s/Portainer.
* **libvirt/QEMU/KVM only**. `Cockpit Machines` stays as raw UI.
* **Authentik is identity DB** – NAS stores only `authentikId → uid/gid/objectId` projections.
* **Extend `service-registry.nix` + `schemas/service-registry.schema.json` → `service-registry v2`** – don’t create a second registry.
* **NAS owns policy** (`/var/lib/nas-control/services.db`), downstream (Caddy, firewalld, Podman, libvirt, Authentik) executes it.
* **No `nas-appd`** – only `nas-service` oneshot + `Caddy` + `firewalld` + `Authentik` + `Podman`/`libvirt`.

---

## 3. Current 2.2.6 Foundation to Reuse

* `service-registry.nix` → `/etc/nas-control/endpoints.json` (fields `label, publicPath, port, units, access, available, linkKey`)
* `web/portal/index.html` (Caddy `templates` + `Remote-*`)
* `caddy-helpers.nix` (strip untrusted `Remote-*`, copy `X-Authentik-*` → `Remote-*`; add `X-Authentik-Uid` in v2)
* `nas_feature_control.py` gate (`GATE_SCOPES` static) → refactor to dynamic `service:<id>:<endpoint>` scopes, mtime cache
* `nas_operation_lock.py` + `nas_operation_journal.py` + `nas-secret-transaction.sh`
* Podman (always) + libvirt (`qemu_kvm, swtpm, virtiofsd, bridges`)

---

## 4. Target Architecture

```
Cockpit Applications UI → nas_cockpit_api (allow-list) → nas-service (oneshot)
                                   ↓
                     service-registry v2 (/var/lib/nas-control/services.db)
                                   ↓
            ┌──────────────────────┼──────────────────────┐
            ↓                      ↓                      ↓
     Runtime adapter          Exposure adapter       Access adapter
   Podman / Compose / libvirt   Caddy / firewalld   Authentik / NAS gate → portal
```

Effective projection is never queried live: renderer writes `/run/nas-control/effective-endpoints.json` and `/run/nas-control/portal.json` after each mutation/reconcile; Caddy templates read only those.

---

## 5. Service Registry v2 — Concrete Schema

### 5.1 Files

```
/etc/nas-control/endpoints.json          # immutable Nix built-ins
/var/lib/nas-control/services.db         # SQLite, WAL, foreign_keys=1
/run/nas-control/effective-endpoints.json # merged + sanitized, mode 0644
/run/nas-control/portal.json              # portal-safe subset, mode 0644
/var/lib/nas-control/services.export.json # human-readable export
```

### 5.2 SQLite DDL (v2)

```sql
CREATE TABLE services (
  id TEXT PRIMARY KEY CHECK (id GLOB '[a-z][a-z0-9-]*' AND length(id) BETWEEN 1 AND 48),
  label TEXT NOT NULL,
  description TEXT,
  ownership TEXT CHECK (ownership IN ('system','runtime')) NOT NULL,
  enabled INTEGER NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE runtimes (
  service_id TEXT PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
  type TEXT CHECK (type IN ('quadlet','compose','vm','external','native')) NOT NULL,
  project TEXT, -- compose project
  source TEXT NOT NULL, -- /var/lib/nas-control/apps/<id>/compose.yaml etc.
  start_policy TEXT CHECK (start_policy IN ('boot','manual','on-demand','disabled')) NOT NULL
);
CREATE TABLE resources (
  service_id TEXT PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
  memory_bytes INTEGER CHECK (memory_bytes BETWEEN 67108864 AND 68719476736),
  cpus REAL,
  gpus TEXT -- JSON
);
CREATE TABLE storage (
  id INTEGER PRIMARY KEY,
  service_id TEXT REFERENCES services(id) ON DELETE CASCADE,
  host_path TEXT NOT NULL CHECK (host_path GLOB '/*'),
  guest_path TEXT NOT NULL,
  mode TEXT CHECK (mode IN ('ro','rw')) NOT NULL,
  dataset TEXT, -- tank/apps/<id>
  UNIQUE(service_id, guest_path)
);
CREATE TABLE endpoints (
  id TEXT NOT NULL,
  service_id TEXT REFERENCES services(id) ON DELETE CASCADE,
  transport TEXT CHECK (transport IN ('http','https','tcp','udp','ws')) NOT NULL,
  target_service TEXT, -- compose service
  target_port INTEGER CHECK (target_port BETWEEN 1 AND 65535),
  exposure_type TEXT CHECK (exposure_type IN ('none','path','hostname','dns','port')) NOT NULL,
  exposure_value TEXT, -- /apps/foo, foo.local, foo.example.net, :9443
  auth_mode TEXT CHECK (auth_mode IN ('public','forward-auth','oidc')) NOT NULL,
  PRIMARY KEY (service_id, id)
);
CREATE TABLE endpoint_authorization (
  service_id TEXT, endpoint_id TEXT,
  mode TEXT CHECK (mode IN ('any','groups','users','all','any-group')) NOT NULL,
  authentik_group_ids TEXT, -- JSON array of stable IDs
  authentik_user_ids TEXT,
  FOREIGN KEY (service_id, endpoint_id) REFERENCES endpoints(service_id, id) ON DELETE CASCADE
);
CREATE TABLE network_policy (
  service_id TEXT PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
  outbound_default TEXT CHECK (outbound_default IN ('allow','deny')) NOT NULL DEFAULT 'deny',
  lan_access INTEGER NOT NULL DEFAULT 0,
  allowed_egress TEXT -- JSON [{cidr, ports}]
);
```

*Validation before write:* `serviceId`/`endpointId` regex, `image`/`project`/`hostname`/`port`/`path`/`CIDR`/`AuthentikId` checks, `PROTECTED_HOST_PATHS` deny, `STRICT_PORTS` check against `ports:` in Compose, `x-nas` as hint only.

### 5.3 Merge

`nas-service registry rebuild`: read `/etc/nas-control/endpoints.json` + `services.db` → validate → write `/run/.../effective-*.json` with `generation` monotonic. No Caddy template reads SQLite.

---

## 6. Runtime Adapters

* **Quadlet** for simple containers; **Compose** for multi-service apps (`podman-compose` pinned, `x-nas` hints shown in plan diff). `podman compose up -d` / `down` via systemd oneshot, no resident compose.
* **libvirt** only: `<metadata><nas:service><id><generation></nas:service></metadata>` tags ownership; `virtiofsd` for host shares.

Adoption flow: `nas-service adopt --type {container,compose,vm} --id <id>` previews plan without recreating workload.

---

## 7. Endpoints & Caddy

Exposure: `none | path (/apps/foo) | hostname (foo.local via Avahi) | dns (foo.home.example.net) | port (:9443) | raw TCP/UDP`. Each gets deterministic Caddy route ID `nas-<service>-<endpoint>`.

Generated Caddy fragment is validated (`caddy fmt` + `caddy validate --config`), applied via `POST /load` on `127.0.0.1:2019` (never exposed to LAN), verified with `GET /config/apps/http/servers/...`, rolled back on failure. Header chain adds `Remote-Uid`.

---

## 8. Auth & Portal

* `public` / `any authenticated` / `groups` / `users` / `all` + `admin bypass`.
* **Dynamic gate:** `GATE_SCOPES = {"", "admin", "authenticated", "network", "ai-api", *CAPABILITY_GROUPS, *{f"service:{s}:{e}"}}` resolved against effective registry; unknown scope = 403.
* Portal: `portal.json` filtered per `Remote-User`/`Remote-Groups`/`Remote-Uid`; visibility ≠ security.

---

## 9. Firewall (firewalld policies, D-Bus)

Presets: `isolated-web` (Caddy in, DNS+HTTPS out, LAN deny), `web+lan`, `backend` (app-to-app only), `lan-service` (raw forward), `custom`. `StrictForwardPorts=yes` only after VM proof that Podman still works. Raw forwards via `firewall-cmd --add-forward-port` under policy; unknown = deny; delete = remove.

---

## 10. Storage, Secrets, Resources

* Host path validation: `realpath` + `relative_to` approved root + `lstat` no symlink escape + `PROTECTED_HOST_PATHS` check; ZFS dataset `tank/apps/<id>` with `quota`/`refquota` via `zfs-tools.nix`.
* Secrets: `secret://applications/<svc>/<key>` → KeePass `ai-provider-*` style, rendered at `podman run --secret` or `env_file` from `/run/nas-secrets/apps/<svc>.env` (0400), never in `services.db`/`effective.json`/`portal.json`.
* Resources: memory `64M–64G`, `cpus`, `pids-limit`, `capabilities` allow-list, `devices/GPU` explicit, `privileged` needs advanced+warning.

---

## 11. Management Command

```
nas-service list | show <id> | validate <file> | plan <file> | create <file> | update <id> <file>
          | delete <id> | start/stop/restart <id> | reconcile [--all] | adopt ... | export/import
```

Adapters under `services/nas_service_*.py` (model, store, registry, podman, compose, libvirt, caddy, firewall, authentik, storage, portal, reconcile). Cockpit calls only `nas_cockpit_api` allow-list.

---

## 12. Transactions

```
acquire_operation("managed-service", ("runtime","secrets","network","storage"))
→ validate → plan diff → journal.json (desired, generation, previousChecksums)
→ Caddy validate → firewalld D-Bus → Authentik app/provider → storage dataset → Podman/libvirt
→ verify (systemd, curl, virsh) → atomic SQLite commit → effective.json → journal complete → release
```

Rollback on any step: remove Caddy route, firewall rule, Authentik objects, Quadlet, dataset if empty+created-by-tx. Never delete pre-existing user data. Reconcile on boot (`nas-service reconcile --all` oneshot) regenerates effective files and restores missing routes.

---

## 13. State, Security, Observability

* `nas_state.py` new authority `managed-services` (`/var/lib/nas-control/services.db` + `/var/lib/nas-control/apps/<id>/`) with `0700` root; Authentik DB remains separate.
* Input validation per §24 (IDs, images, hostnames, CIDRs, libvirt XML, `X-Authentik-*`), no `shell=True`, no Caddyfile injection.
* Compose scanner flags `privileged, hostNetwork, socket mounts, / mounts, /dev, caps, sysctls`.
* Observability reuses `victoriametrics` when enabled; otherwise `podman inspect --format`, `virsh dominfo`, `systemctl show` on Cockpit poll.

---

## 14. Tests (add to §26)

* Unit: schema, validation, registry merge, portal filter, Caddy/firewall renderers, adapters, plan diff, v1→v2 migration, rollback.
* Fuzz: 250 cases each for `serviceId, endpointId, image, compose, hostname, port, path, CIDR, AuthentikId, libvirt metadata` plus Trojan Source / YAML anchors.
* Auth: anonymous / authz-fail / group / user / admin / renamed group / forged `Remote-*` / forged `X-Authentik-*`.
* Caddy: path/hostname/port, WebSocket, HTTPS upstream, duplicate hostname, reserved path.
* Firewall: Caddy-only, LAN deny, app-to-app, TCP/UDP forward, reboot reconcile.
* Compose: `db+web` + volume + secret + healthcheck + start/stop/reboot, prove `podman-compose` exits.
* VM: `qemu-test.sh` + `test/qemu/harness.sh` (no-sudo) with `virtiofs` + Caddy→VM + TCP forward + reboot persistence.
* Journal: inject failure after each apply step, assert `services.db` unchanged and no orphan route.

---

## 15. Phases (effort S/M/L, risk)

1. **Schema + store** (M, low) — v2 DDL, migration, effective projection, `state` authority. Exit: Cockpit lists built-ins + mock runtime via one API.
2. **Portal** (S, low) — `portal.json`, `Remote-Uid`, generic Caddy template. Exit: built-ins render from registry.
3. **Gate** (S, medium) — dynamic `service:*` scopes, mtime cache. Exit: synthetic endpoint protected without Nix rebuild.
4. **Podman single** (M, medium) — Quadlet, mounts, resources, journal. Exit: `nas-service create` → Caddy `https://<id>.local` with Authentik.
5. **Compose** (L, medium) — `podman-compose` provider, `x-nas` hints, scanner. Exit: multi-container `immich` survives reboot, no resident compose.
6. **Caddy exposure** (M, low) — path/hostname/dns/port, conflict detection, zero-downtime `POST /load`. Exit: edit exposure without restart.
7. **Firewall** (M, high) — policies, egress/LAN, app-to-app, raw forward, cleanup. Exit: `curl 8.8.8.8` denied when profile says deny (VM proof).
8. **VM** (L, medium) — adopt/create, `virtiofs`, libvirt metadata, forwards. Exit: VM web same UI as container.
9. **Authentik OIDC** (M, low) — app/provider/binding/secret injection. Exit: supported app gets native OIDC without Authentik UI.
10. **Cockpit wizard** (L, low) — 9-step wizard + plan diff. Exit: no need for raw Podman/Machines.
11. **Built-in consolidation** (S, low) — move helper containers to same adapter where it deletes code.
12. **Hardening** (M, low) — fuzz, ZAP, memory, docs. Exit: all §14 pass.

---

## 16. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Compose `ports:` bypasses firewall | Detect published ports → warn/reject unless `exposure` object exists; prefer `127.0.0.1:<port>` for Caddy-only |
| `x-nas` becomes hidden authority | Show diff before apply; treat as hint only |
| libvirt XML drift | Store `generation` in `<metadata>`; reconcile compares generation, not full XML |
| Authentik ID rename | Fail closed, surface “group `Family` (id `...`) not found” in Cockpit |
| SQLite WAL growth | `VACUUM` on export, `journal_mode=WAL` + `auto_vacuum` |

---

## 17. Definition of Done — unchanged from v1 §35, plus “no shellcheck -S warning failures on `scripts/preflight.sh`” and “VM `test/qemu/harness.sh test` reports `flake_check_exit` as expected only on placeholder `installationReady=false`”.

---

## 18. VM Harness Notes (from Alpha.6 validation)

* Host `pytest` without `/var/lib` mocks fails with `PermissionError: /var/lib/nas-control`; authoritative tests are inside VM via `nix-shell /tmp/shell.nix --run 'pytest tests -q'` (422 passed, 1 `shellcheck` warning remaining) or `test/qemu/harness.sh test` (expected `fileSystems`/`boot.loader` failure when `installationReady=false`).
* Version contract: `VERSION`, `README`, `flake.nix:description`, `cockpit/package.json:version`, `docs/development/artifact-naming.md` must stay in sync — Alpha.6 was re-provisioned via `rsync --delete` after `sed -i 's/2.2.0-alpha.5/2.2.0-alpha.6/'`.

---

## 19. File-Level Touchpoints (v2)

```
schemas/service-registry.schema.json, schemas/managed-service.schema.json
modules/nas/internal/service-registry.nix, modules/nas/config/system.nix,
modules/nas/config/virtualization.nix, modules/nas/config/reverse-proxy.nix,
modules/nas/internal/caddy-helpers.nix, modules/nas/internal/account-tools.nix
services/nas_service_*.py, services/nas_common.py, services/nas_feature_control.py,
services/nas_cockpit_api.py, services/nas_state.py
web/portal/index.html
cockpit/src/app.jsx, cockpit/src/api.js, cockpit/src/view-model.js
tests/test_managed_service_*.py, tests/nixos/managed-*.nix
```

---

*End — implement per phase order §15; any second runtime/identity/portal/daemon is a deviation.*
