# V2 Minimization Plan — Replace Custom Code with Existing NixOS/Upstream

**Goal:** Cut ~40% of `services/nas_v2*.py` (10k lines → ~6k) by delegating to already-tested NixOS and upstream units. V2 stays a finite compiler/provisioner over native systemd, Podman, Caddy, Authentik, firewalld, Restic/ZFS — it does not become a daemon.

## 1. What is custom and can be replaced

| Custom file | Lines | Existing replacement | Savings | Risk |
|---|---|---|---|---|
| `nas_v2_accelerator.py` | 280 | `hardware.nvidia.modesetting`, `hardware.opengl`, `virtualisation.oci-containers` cdi `pkgs.nvidia-container-toolkit`; Nix already exposes `/dev/dri` and `nvidia.com/gpu` CDI | 280 | Low — upstream CDI is tested |
| `nas_v2_podman_network.py` + `nas_v2_firewalld.py` + `nas_v2_firewalld_reconcile.py` | 514+424+~200 | `networking.firewall`, `virtualisation.podman.defaultNetwork.settings`, `networking.firewall.interfaces` | ~900 | Low — NixOS firewall is declarative |
| `nas_v2_session.py` + `nas_v2_session_projection.py` | 403+426 | `systemd-run --scope --property DynamicUser=yes --property RemoveOnSuccess=yes` + `systemd` `DynamicUser`/`StateDirectory`; no custom vape | ~800 | Medium — need to preserve `RemoveOnSuccess` |
| `nas_v2_backup.py` + `nas_v2_backup_runtime.py` + `nas_v2_native_dump.py` + `nas_v2_backup_verify.py` | ~250 | `services.restic.backups`, `services.sanoid.datasets`, `systemd.services.*.serviceConfig.ExecStart` with `pg_dump`/`sqlite3 backup` | ~200 | Low — Restic is upstream |
| `nas_v2_caddy.py` (405) + `nas_v2_portal.py` | 405+~100 | `services.caddy.virtualHosts` + `services.caddy.extraConfig` templated from `services.yaml` via `pkgs.writeText` at activation time (not Nix eval); use `caddy adapt --adapter caddyfile` for validation | ~300 if we keep thin translator | Medium — need to keep `forward_auth` + `trustedIdentityHeaders` |
| `nas_v2_compose.py` / `nas_v2_quadlet.py` / `nas_v2_libvirt.py` | 437+415+340 | `virtualisation.oci-containers`, `virtualisation.podman`, `virtualisation.libvirtd` with `systemd.services` overrides | Could be thin shims (100 each) | Low |

**Not removable:** `nas_v2_spec.py` (YAML 1.2 + JSON Schema + semantic validation), `nas_v2_bootstrap.py` (seed-once), `nas_v2_apply.py`/`nas_v2_plan.py` (transaction orchestration), `nas_v2_editor.py`/`nas_v2_control.py` (finite edit API, now revision-safe), `nas_v2_systemd.py` core dependency/topology (844 lines — can be trimmed to ~500 by delegating device/GPU/network to Nix).

## 2. Concrete steps (in order, bisectable)

1. **Accelerator:** Delete `nas_v2_accelerator.py`, `tests/test_v2_accelerator.py` references. In `modules/nas/config/managed-services-seed-v2.nix` keep `resources.accelerators` as data, but `nas_v2_apply.py` no longer calls `resolve_effective`; instead emit `systemd.services.<unit>.serviceConfig.DeviceAllow` and `Environment="NVIDIA_VISIBLE_DEVICES"` via Nix `hardware.nvidia` when `accelerators[].vendor == "NVIDIA"`. Use `is_cdi_selector` inline regex.
2. **Podman/Firewall:** Delete `nas_v2_podman_network.py` + `nas_v2_firewalld.py`. In `modules/nas/config/network-firewall.nix` set `networking.firewall.allowedTCPPorts` from `services.yaml` via a small `systemd` generator that reads `/run/nas-control/effective.json` and writes `/run/nas-control/firewalld.json` — no custom Python, just `jq`. Or use `networking.firewall.extraCommands` with `iptables -A`.
3. **Sessions:** Delete `nas_v2_session*`. Replace `nas_v2_wake.py`'s `systemd-run` call with `systemd-run --unit=nas-v2-session-%i --scope -p DynamicUser=yes -p StateDirectory=nas-v2-sessions/%i -p RemoveOnSuccess=yes /run/current-system/sw/bin/podman run --rm ...`. No V2 session DB.
4. **Backup:** Delete `nas_v2_backup*.py` custom inventory. Use `services.restic.backups.nas-boot-system` with `paths = [ "/var/lib/postgresql" ]` and `services.sanoid.datasets."tank/nas".autosnap = true;`. Keep only `nas_v2_backup_runtime.py`'s freshness check (48 lines) as a `systemd` `ExecStartPre` that `rm -rf $artifact &&` `pg_dump`.
5. **Caddy:** Trim `nas_v2_caddy.py` to 150 lines: only render `forward_auth`, `trustedIdentityHeaders`, `stripPrefix`, `requireHeaders`. Move `caddyOnDemandTransport` and `caddyForwardAuth` strings to `modules/nas/internal/caddy-helpers.nix` (already there). Validate with `caddy adapt`.

## 3. Expected outcome

- `services/` from 32 files → ~22 files, ~6k lines.
- `modules/nas/config/managed-services*.nix` from 7 files → 4 files (seed aggregation already done).
- No second account/share/secret DB; NixOS, Authentik, CopyParty, KeePassXC, Syncthing remain sole authorities (already in `invariants.md`).
- `services.yaml` stays sole mutable authority at `/var/lib/nas-control/services.yaml`; Nix never regenerates it.
- All remaining V2 Python is pure validation/projection with no resident daemon (already achieved).

## 4. Validation

- Keep `tests/test_v2_spec.py` (fail-closed parsing) and `tests/test_v2_seed_aggregation.py` (seed-once).
- Add `tests/test_v1_regression.py` (already) to forbid `nas-feature-control` etc.
- Run `nix develop .#test -c ./scripts/run-unit-tests.py --jobs 4` and `node --test tests/js/*.test.mjs` — must stay green.
- `nix develop .#qemu-test -c ./scripts/qemu-test.sh all` remains non-blocking (currently broken).

## 5. Docs to update

- `docs/development/code-map.md`: remove deleted files, point to `managed-services-seed-v2.nix`.
- `docs/development/architecture.md`: replace "feature controller owns feature lifecycle" with "V2 `services.yaml` owns lifecycle; Caddy+Authentik owns auth".
- `docs/development/invariants.md`: delete feature-controller line, add V2 seed-once invariant.
- `docs/development/README.md`: note `./tmp` inside project for local packaging.
