# Caddy First-Boot Bootstrap — Implementation Plan

**Status:** Implemented and validated.
**Branch:** `agent/managed-services-v2-simplify-v2`

## 1. Objective

Caddy is the only HTTPS front door (`:443`) on every boot, from first power-up through
steady state:

- **First boot (pre-secrets):** Nix renders a *bootstrap* Caddy config. No
  `${secretRoot}/ready`, no Authentik, no V2 fragment. Serves the portal
  (setup guide / first-account helper) plus `/console` (Cockpit reverse-proxied to
  loopback, `tls internal`, own internal CA). Cockpit listener stays
  loopback-only; it never opens a LAN port.
- **After first-run + reboot:** the running system's V2 pipeline produces the full
  config. Caddy starts with it and keeps it fresh via the existing V2 update path.

## 2. How V2 already updates Caddy (do not reinvent)

From `modules/nas/config/managed-services.nix`:

- `nas-managed-services-reconcile.service` compiles desired state and writes
  `/run/nas-control/caddy-managed.conf` (`NAS_V2_CADDY`), which defines the Caddyfile
  snippet `(nas_v2_managed_paths)`.
- The nixpkgs caddy module composes the Caddyfile from `globalConfig` + `extraConfig`
  + `virtualHosts`; `managed-services.nix` appends:
  - `services.caddy.extraConfig` (mkAfter) → `import /run/nas-control/caddy-managed.conf`
  - `virtualHosts.${lanHost}.extraConfig` (mkBefore) → `import nas_v2_managed_paths`
- `systemd.paths.nas-managed-services-caddy-reload` watches `caddyManagedPath`
  (`PathChanged`) → `nas-managed-services-caddy-reload.service` →
  `systemctl reload caddy.service`.

So every V2 route change re-renders the fragment and reloads Caddy. Keep this path
exactly as it is for the post-secrets world.

## 3. Problem: same generated config can't serve both phases

The nixpkgs caddy module bakes one Caddyfile (store path exposed at
`/etc/caddy/caddy_config`). Pre-secrets:

- The V2 desired-state seed and reconcile run before first-run creates or mounts the
  ZFS pool. `tmpfiles` creates their root-filesystem directories; the later ZFS mount
  shadows those directories. Protected runtime services still wait for
  `nas-zfs-mount-guard`.
- forward-auth blocks point at an Authentik outpost that is not running → portal dead.

Hence a separate bootstrap config that has none of those, and a runtime selector that
picks bootstrap vs full.

## 4. Design: selector + first-boot bootstrap writer

### 4.1 Two configs, both rendered by Nix

1. **Bootstrap** — `pkgs.writeText` Caddyfile with:
   - `tls internal`, main `https://${lanHost}` site.
   - Portal static root (`${nasPortalStatic}/share/nas-portal`) via Caddy `templates`.
   - `handle /console*` → `reverse_proxy 127.0.0.1:${cockpitPort}` (just the
     reverse proxy; no forward-auth pre-secrets. No admin password exists yet, so
     Cockpit's own PAM login is the actual gate).
   - `/identity/*` Authentik proxy may be included only if harmless pre-secrets;
     otherwise omit and note it in the plan.
   - No `import` of V2 fragment, no forward-auth.

2. **Full** — the existing nixpkgs-module-generated config (unchanged; this is what
   `/etc/caddy/caddy_config` already points at, including the V2 imports above).

### 4.2 Runtime selector: `nas-caddy-bootstrap.service` (oneshot)

- `Type = oneshot; RemainAfterExit = true`.
- Runs `before = [ "caddy.service" ]`; caddy `after` it (replaces caddy's direct
  `requires = nas-managed-services-reconcile` coupling, see limitations).
- ExecStart logic:
  - If `${secretRoot}/ready` exists: `systemctl start nas-managed-services-reconcile.service`
    (ignore failure), and if `/run/nas-control/caddy-managed.conf` now exists write
    `/run/nas-control/caddy-active.conf` containing `import /etc/caddy/caddy_config`;
    otherwise (still pre-setup) write the bootstrap import.
  - Else (pre-secrets): write `import ${bootstrapCaddyfile}` to
    `/run/nas-control/caddy-active.conf`.
- **Self-disable / pass-through:** after first boot it is a trivial
  ready-check + one `import` line. Either
  (a) always run the cheap check every boot, or
  (b) gate with a `ConditionPathExists`/state file so later boots skip.
  Simplest: option (a) — the check costs ~nothing and needs no self-removal logic.

### 4.3 Point Caddy at the active file

Override `systemd.services.caddy.serviceConfig.ExecStart`/`ExecReload` to run against
`--config /run/nas-control/caddy-active.conf --adapter caddyfile`, instead of the
module's baked `/etc/caddy/caddy_config`. Keep everything else the module sets
(EnvironmentFile, User/Group, sandboxing).

### 4.4 Relax caddy gating for bootstrap

In `modules/nas/config/systemd-services.nix` caddy unit:
- Drop `ConditionPathExists = ${secretRoot}/ready` (the bootstrap phase must start
  pre-secrets).
- Drop hard `requires = nas-managed-services-reconcile.service` / authentik &
  reconcile `after` (pre-secrets they fail/skip and would block caddy). Ordering vs
  reconcile is enforced inside `nas-caddy-bootstrap.service` instead.
- Keep `wants = caddyBackendUnits`; protected-services wiring as-is.

Verify the following don't regress:
- `nas-managed-services-wake.socket` — keep `before = [ "caddy.service" ]`.
- `nas-caddy-ca-export` / vaultwarden OIDC — post-secrets only, unaffected.

## 5. First-run → reboot handoff

- `nas-setup first-run` completes password/credential setup → writes secrets →
  `${secretRoot}/ready`.
- Trigger **a full reboot** (explicit, so reconcile/ZFS/authentik/V2 all start clean and
  caddy comes up with the full config). Decide: auto-reboot from first-run, or instruct
  the user (open question below).

## 6. Second boot / steady state

- Secrets exist, ZFS decrypted, reconcile writes the V2 fragment, selector picks
  `import /etc/caddy/caddy_config` → caddy runs full config.
- V2 route changes flow through the existing path unit + reload (section 2). Nothing
  new needed here.

## 7. Working-tree snapshots already in place (do not regress)

- `system.nix` — cockpit socket always loopback-only.
- `network-firewall.nix` — owned zone has only `443/udp`; guard no longer conditioned
  on `directCockpitRecovery`.
- `core.nix` — `directCockpitRecovery` deprecated.
- `local.nix` — `directCockpitRecovery = false`.

## 8. Decisions (confirmed with operator)

1. **Reboot after first-run: explicit `systemctl reboot`.** `nas-setup first-run`
   triggers a real reboot once secrets are written so secrets/ZFS/reconcile/V2 and
   Caddy all start clean with the full config. No live in-place switch.
2. **Authentik pre-secrets: omitted.** Operator preferred a default Authentik admin
   on first boot "if you can"; not feasible — `authentik`/`authentik-migrate` are
   gated on `${secretRoot}/ready` and their env file comes from the secret store, so a
   *working* pre-secrets Authentik contradicts the no-secrets-before-setup model.
   Bootstrap Caddy serves only portal + `/console`; `/identity/*` appears once the
   full config activates after the first-run reboot.
3. **Selector runs every boot** — cheap ready-check + one `import` line (no
   self-disable flag; state variant is the fallback if timing shows up).

## 9. Remaining constraints

1. **Caddy authorization surface pre-secrets:** `/console` has only Cockpit's own PAM
   gate (no admin password exists yet → effectively locked), and no forward-auth.
   Acceptable, documented.
2. **ExecStart/ExecReload override vs module** — verify `adapter caddyfile` and that
    `reloadTriggers`/`restartTriggers` (baked store path) don't fight the runtime file.
    Validate in VM.

The persistent QEMU suite passed after the pre-ZFS seed/reconcile ordering change.

## 10. Verification path (VM)

```bash
ssh -p 2222 -i ~/.cache/nixos-nas-qemu/state/installer-admin-ed25519 \
  -o StrictHostKeyChecking=no admin@127.0.0.1
# pre-secrets: caddy active with bootstrap config, portal + /console reachable via :443
curl -sk https://127.0.0.1:443/ | grep -i "nas"          # portal
curl -sk https://127.0.0.1:443/console                   # cockpit via caddy
sudo cat /run/nas-control/caddy-active.conf
sudo ss -tlnp | grep -E '9092|9090|:443|9094'            # no direct cockpit listener
```
