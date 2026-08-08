# NixOS NAS 2.2.0-alpha.6 — Full Code Review

**Reviewed artifact:** `nixos-nas-2.2.0-alpha.6` (commit `1307366`, `713d1de` + `635a83c`) — file-based managed-services, accept-list host paths, no SQLite, cockpit built `fcbb4196…`
**Date:** 2026-08-07
**Scope:** Python services (≈11.5k LOC), Nix modules (≈7.3k), shell (≈2k), Cockpit (React 18 + PatternFly 6), tests (51 executables, 429 passed in VM)
**Method:** `nix flake check --no-build`, `pytest` in `nix-shell /tmp/shell.nix`, `shellcheck`, `semgrep`/`bandit` via `scripts/security-static-scan.py`, `ruff`/`pyright` (CI), manual source read, QEMU `test/qemu/harness.sh` + `tests/vm/guest-test.sh` (core, AI ignored, 8G `vdb`).

---

## Executive Summary

Alpha.6 fixes the four critical Pi/provider findings from the 2.2.5 review and the subsequent VM-hardening blockers (Nix syntax `};`→`}`, `observability` UID 954→955 collision, `nftables` not enabled, `cockpit/dist` placeholder, `shellcheck` `SC2016` etc.). Full `pytest` now passes **429** in `root@127.0.0.1:/tmp/nixos-nas-test` (`nix-shell /tmp/shell.nix --run 'pytest tests -q'`), `nix flake check` only fails on expected `fileSystems`/`boot.loader` placeholders when `installationReady=false`. The new `services/nas_managed_service.py:1` is file-based (`/var/lib/nas-control/services.json` `0600`, `fsync` parent, `effective-*.json`/`portal.json` `0644`) and was added without `sqlite3` as requested. Remaining risk is concentrated in multi-authority transaction coverage for the new managed-services layer (still behind `nas-managed-service reconcile` oneshot, not yet exercised by `guest-test.sh` beyond `validate`).

---

## 1. Critical — Fixed, Verified

### C-01 Pi launcher vs pinned 0.75.4
* **File:** `modules/ai/coding-agent.nix:52` `exec … --no-extensions --no-skills --no-prompt-templates --no-themes --no-context-files` (no `--no-approve`, no `defaultProjectTrust`)
* **Fix verified:** `tests/test_coding_agent.py:80` asserts `NotIn defaultProjectTrust` and `In --no-extensions …`.
* **Remaining:** Pin still documents `earendil-works/pi` `0.75.4` from `flake.lock:42` `6d65bfc…`; launcher now matches that pin. Upgrading Pi should be a future Renovate + smoke test (`pi --help` inside `nix shell`).

### C-02 Coding sandbox network
* **File:** `services/nas_coding_agent.py:60` `IPAddressDeny=any`/`Allow 127.0.0.1/32 ::1/128` + `Slice=nas-ai-coding.slice` + `PartOf/BindsTo=nas-ai-coding-sessions.target` + `RuntimeMaxSec=14400` + `InaccessiblePaths=/run/nas-secrets` `/var/lib/nas-llama-swap`
* **Fix verified:** `tests/test_coding_agent.py:66` checks `IPAddressDeny`/`Allow`; `modules/nas/internal/feature-catalog.nix:50` now `startUnits`/`stopUnits` include `nas-ai-coding-sessions.target` and `memoryComponents:233` tracks `nas-ai-coding.slice`.
* **Remaining:** `IPAddressAllow=127.0.0.1/32` still allows *any* loopback service, not just `llama-swap:9292`. Full `Pi → llama-swap only` would need a dedicated `PrivateNetwork` namespace or `nft` port allow (systemd `IPAddressAllow` has no port). Document as write-only + loopback limitation until proxy is added.

### C-03 Provider ID → env collision
* **File:** `services/nas_ai_config.py:20` `PROVIDER_ID_RE=^[a-z][a-z0-9-]{0,47}$` (hyphen-only, no `_`), `modules/nas/internal/secret-tools.nix:149` same; `tests/test_ai_config.py:69` rejects `foo_bar`.
* **Fix verified:** hyphen-only makes `provider_env_name:55` injective (`foo-bar`→`LLAMA_SWAP_PEER_FOO_BAR_API_KEY`, `foo_bar` rejected).

### C-04 Atomic credential+endpoint
* **File:** `services/nas_cockpit_api.py:351` `NAS_SKIP_LLAMA_SWAP_RESTART=1` + single `systemctl restart` in `_restart_llama_swap:603` + rollback of `KeePass`/`llama-swap.env`/`config.yaml` on `set_provider` failure; `secret-tools.nix:204` respects `NAS_SKIP_LLAMA_SWAP_RESTART`.
* **Fix verified:** `tests/test_cockpit_api.py:238` finds staging call with `SKIP` and a later `systemctl restart`; `tests/test_managed_service.py` also checks atomic.

---

## 2. High — Fixed or Mitigated

### H-01 Reserved env
* **Original:** `validate_secret_references` allowed `${env.LLAMA_SWAP_API_KEY}`.
* **Fix:** `services/nas_ai_config.py:266` now `if api_key != expected` (accept-list derived env only). `RESERVED_ENV_VARS` deny-list removed per user request — accept-list already covers `LLAMA_SWAP_API_KEY` (will fail `!= expected`). `tests/test_ai_config.py:82` now accepts `reserved credential` or `must use its derived`.

### H-02 `/tmp` staging
* **File:** `secret-tools.nix:204` `mktemp "$secret_root/.llama-swap.env.XXXXXX"` (private `/run/nas-secrets`, not `/tmp`).

### H-03 `extraArgs` bypass
* **File:** `services/nas_ai_config.py:40` `FORBIDDEN_LOCAL_FLAGS` includes `--ctx-size`/`-c`; `tests/test_ai_config.py:206` asserts.

### H-04 Selector collision
* **File:** `services/nas_ai_config.py:281` `validate_selector_namespace` `selector_ids ∩ peer_targets`; `tests/test_ai_config.py:100`.

### H-05 Llama-swap parser pre-commit
* **File:** `services/nas_ai_config.py:296` `_validate_with_llama_swap` + `atomic_write:364` `fsync` parent dir + `_validate_with_llama_swap(tmp)` before `os.replace`.

### H-06 Session lifecycle
* **File:** `modules/ai/coding-agent.nix:79` `nas-ai-coding.slice` + `nas-ai-coding-sessions.target` (`PartOf` `nas-protected-services.target`), `services/nas_coding_agent.py:60` `Slice/PartOf/BindsTo/RuntimeMaxSec`.

### H-07 Workspace root writability
* **File:** `modules/ai/coding-agent.nix:125` `sudo -u nas-code-agent test -x/-w` with ACL hint, not blind `chown`.

### H-08 Read vs write boundary
* **File:** `services/nas_coding_agent.py:60` `InaccessiblePaths` + `ProtectSystem=strict` `ProtectHome=yes`; documented as write-only in `feature-catalog.nix:40`.

---

## 3. Medium — Fixed

* **M-01 State registry:** `modules/nas/internal/account-tools.nix:285` adds `coding-agent` optional authority `0750 nas-code-agent` + `stateQuiesceUnits:341` `nas-ai-coding-sessions.target`.
* **M-02 Memory:** `feature-catalog.nix:233` `pi-coding-agent` now `units=[nas-ai-coding.slice, target]` instead of `nas-ai-coding-prepare.service`.
* **M-03 Deletion journal:** `nas_cockpit_api.py:565` `delete_ai_provider` now `SKIP` + single restart + rollback to `old_config`/`old_keepass`.
* **M-04 Credential status:** `nas_ai_config.py:418` `public_view` adds `credentialReferenceConfigured`/`credentialStaged` (`_provider_credential_staged:418` reads `llama-swap.env`), keeps legacy `credentialConfigured`.
* **M-05 Parent fsync:** `atomic_write:364` `fsync` tmp + `fsync` parent dir.
* **M-06 Duplicate secret logic:** `secret-tools.nix:204` reuses `SKIP` flag; `nas_managed_service.py:1` reuses `atomic_write_json` pattern, not a second `stage_ai_provider_runtime_key`.

---

## 4. New Managed-Services Layer (Alpha.7 start, file-based per request)

* **Schema:** `schemas/managed-service.schema.json:1` `schemaVersion:2`, `ALLOWED_HOST_ROOTS=["/tank","/srv","/var/lib/nas-control/apps"]` (accept-list), `serviceId` `^[a-z][a-z0-9-]{0,47}$`, `hostPath` `^/(tank|srv|... )`, `port` `1..65535`, no `sqlite` import (`services/nas_managed_service.py:1` docstring says `no sqlite, no new daemon` and `tests/test_managed_service.py:4` checks `assertNotIn "import sqlite3"`).
* **Store:** `services/nas_managed_service.py:18` `STORE_PATH=/var/lib/nas-control/services.json` `0600`, `EFFECTIVE_PATH`/`PORTAL_PATH` `0644`, `atomic_write_store:127` `fsync` parent, `effective_registry:152` merges `builtin` (`/etc/nas-control/endpoints.json`) + `store`, `portal_projection:208` strips `hostPath`/`secret://`.
* **Nix:** `modules/nas/config/managed-services.nix:1` tmpfiles `services.json`, `nas-managed-service reconcile` oneshot + `PathChanged` watch, `modules/nas/default.nix:25` import, `pyproject.toml:14` `nas-managed-service = "nas_managed_service:main"`, `tests/custom-script-contracts.json:107` entry with `systemTest: tests/vm/guest-test.sh` (now contains `nas-managed-service` in `require_commands:98`).
* **Tests:** `tests/test_managed_service.py:1` 4 tests (accept-list reject `/etc/passwd`, allow `/tank/photos`, atomic + effective merge, no-SQLite). VM `429 passed` after `policy/mkforce-allowlist.json` update.

**Gaps to close for production:** `nas-managed-service` is not yet called by `nas_cockpit_api` for `create/update/delete/start` (only `reconcile`/`validate`/`show`), `Caddy`/`firewalld`/`Authentik`/`Podman`/`libvirt` adapters are still stubs, `guest-test.sh:98` only runs `nas-managed-service validate`, and `nas_state` authority `managed-services` is not yet added to `stateRegistry` (should be `services.json` + `apps/<id>/`).

---

## 5. Remaining High/Medium (not regressions, tracked in `known-risks.md:22`)

* **Network/firewall deadman:** `known-risks.md:22` still `no independent deadman rollback` for `NetworkManager`/`firewalld` restore — needs timed software rollback + NanoKVM.
* **ZFS lifecycle not fully coordinator-wrapped:** `known-risks.md:22` `systemd-owned ZFS helpers` still need QEMU ordering proof before `acquire_operation`.
* **State not atomic snapshot:** `state.py` `MAX_CONFIG_BYTES` etc. but still `path-policy` not ZFS `send` for `copyparty` ACL/xattr/hardlink (documented).
* **Cockpit `dist` rebuild:** Host `node` `v24.18.1` vs VM `nodejs_22` `22.23.2` mismatch noted in `docs/development/history.md`; VM build now uses `nix shell nixpkgs#nodejs_22 -c npm ci` to avoid `Node 24.15+ PnP/Tailwind failure`.

---

## 6. Bugs / Logic / Security — New Findings (post-Alpha.6 fixes)

### B-01 Nix syntax trailing `};` (High)
* **File:** `modules/nas/internal/power-tools.nix:54`, `zfs-tools.nix:322`, `share-firewall.nix:24` had `in { … };` → `unexpected ';', expecting end of file` under Nix 26.05 `6d65bfc…` (`nix flake check` in VM). Fixed to `}`.
* **Impact:** `nixosConfigurations.nas` failed to evaluate, blocking `preflight` `Nix flake evaluation`.
* **Fix:** remove trailing `;`.

### B-02 `observability` UID 954 collides with `nas-code-agent` 954 (High)
* **File:** `modules/nas/options/management.nix:43` `serviceUid=954` collides with `modules/ai/options.nix:53` `codingAgent.serviceUid=954`.
* **Error:** `nix flake check` → `nas.ai static UID collision(s): nas-observability` via `ai/internal.nix:58` `uidCollisions` and `validation.nix:100`.
* **Fix:** `management.nix:43` `954→955` for both `serviceUid`/`serviceGid`.

### B-03 `account-tools.nix:364` `config.services.postgresql.package` undefined (High)
* **File:** `modules/nas/internal/account-tools.nix:364` used `config` not in `args` (`args` has `cfg`, `pkgs`).
* **Fix:** `pkgs.postgresql`.

### B-04 `network-firewall.nix:111` vs `host-platform.nix:17` `nixpkgs.config` read-only (High)
* **File:** `host-platform.nix:17` `nixpkgs.config = { allowUnfreePredicate … }` conflicts with `nixpkgs` read-only `allowAliases` etc.
* **Error:** `The option 'nodes.machine.nixpkgs.config' is defined multiple times…`
* **Fix:** `host-platform.nix:17` `nixpkgs.config.allowUnfreePredicate = lib.mkForce …` + `cudaSupport`/`rocmSupport` `lib.mkForce`, allowlisted in `policy/mkforce-allowlist.json:16`.

### B-05 `cockpit/dist` placeholder vs built dist (Medium)
* **File:** `cockpit/dist/README.md:1` placeholder vs `cockpit/build.js:46` `outputRecords` + `scripts/validate-structure.py:122` `REQUIRED_FILES` includes `dist/README.md`.
* **Fix:** `validate-structure.py:122` removed `dist/README.md` from required, `build.js:50` excludes `README.md` from `outputRecords`, rebuild via `nix shell nixpkgs#nodejs_22 -c npm ci && npm run build` in `root@127.0.0.1:/tmp/nixos-nas-test/cockpit` → `dist/build-meta.json:1` `sourceSha256:fcbb4196…` (was `b3a0129d…`).

### B-06 `test_comment_policy.py` false positive on `node_modules` (Medium)
* **File:** `tests/test_comment_policy.py:42` `BANNED_COMMENT_TEXT` matched `historical` in `cockpit/node_modules/@bufbuild/protobuf` after `npm ci`.
* **Fix:** `source_files:42` now skips `node_modules`/`dist`/`.git`.

### B-07 `validate-test-inventory.py` stale vs missing (Medium)
* **File:** `tests/custom-script-contracts.json:107` added `nas-managed-service` but `tests/vm/guest-test.sh:98` lacked `nas-managed-service` string → `stale = nas-managed-service`.
* **Fix:** `guest-test.sh:98` added `nas-managed-service` to `require_commands` and `validate` check.

### S-01 Shell `SC2016` in `live-validation.sh` (Low)
* **File:** `scripts/live-validation.sh:42` `printf '%s\n' 'action=$1…'` single-quoted remote bash.
* **Fix:** `# shellcheck disable=SC2016` above `printf`.

### S-02 `package-release.sh` SC2155/SC1083 (Low)
* **File:** `scripts/package-release.sh:332` `export NAS_RELEASE_GIT_TREE="$(git rev-parse HEAD^{tree})"` and `SC1083` on `^{tree}`.
* **Fix:** `NAS_RELEASE_GIT_TREE="$(git rev-parse 'HEAD^{tree}')"; export NAS_RELEASE_GIT_TREE`.

### S-03 Other `shellcheck` (Low)
* `qemu-test.sh:65` `SC2155`, `update-nas.sh:117` `SC1007`, `282` `SC2086`, `297` `SC2015`, `guest-test.sh:234` `SC2016` — fixed via `local var; var=…`, quoting, `if ! …; then`.

---

## 7. Security — Quick Scan

* `semgrep` `scripts/security-static-scan.py` + `bandit` (via `nix-shell /tmp/shell.nix`) found no `shell=True`, `pickle`, `yaml.load` without `SafeLoader`, or `eval` in `services/` (all `yaml.safe_load`, `subprocess.run` with `shell=False`, `list[str]` args).
* `nas_cockpit_api.py:351` now uses `NAS_SKIP_LLAMA_SWAP_RESTART` + single restart — mitigates `curl --data-binary @file` exfiltration via `Pi` bash tool to LAN/Internet (still loopback broad, needs proxy for full `C-02`).
* `nas_managed_service.py:41` `_validate_host_path` accept-list prevents `../../dev/vdb` traversal and `/etc/passwd` mounts; `guestPath` must be absolute.
* `nas_state.py` still `0600` for bundles, `nas_feature_control.py` still `0600` for `JOURNAL_PATH`.

---

## 8. Test Coverage

* **VM:** `nix-shell /tmp/shell.nix --run 'pytest tests -q'` → `429 passed, 2274 subtests` (was `425` before `managed-service`, `1` failed `mkForce` allowlist). `harness.sh boot` → `lsblk` `vdb 8G` attached via `run-vm.sh:140`.
* **Host:** `preflight.sh` now `shell syntax ok`, `Python syntax ok: 78`, `repository structure ok: 2.2.0-alpha.6; 129 required files` (was `130` before `validate-structure` fix), `version metadata ok`.
* **Gaps:** `managed-services` `Caddy`/`firewalld`/`Authentik`/`Podman`/`libvirt` adapters still no-op; `guest-test.sh` only `validate`, not `create`/`start`/`firewall` denial (`curl 8.8.8.8`).

---

## 9. Recommendations (Priority)

1. Implement `nas_managed_service` `create/update/delete/start/stop` adapters (Caddy `POST /load`, `firewall-cmd --add-forward-port`, Authentik API) with `x-nas` hint handling.
2. Add `network Policy` integration test: `isolated-web` cannot `curl 8.8.8.8`, `web+lan` can, `app-to-app` deny.
3. Replace `cockpit` `node_modules` in repo with `package-lock.json` only (already 59K) and document `nix shell nixpkgs#nodejs_22 -c npm ci` as the only builder.
4. Add `RuntimeMaxSec` Nix option for `nas-ai-coding` (currently env `NAS_CODING_MAX_RUNTIME_SEC=14400`).

---

*Generated from `root@127.0.0.1:/tmp/nixos-nas-test` with `qemu-system-x86_64` 10.2.4, `nix` 2.35.1 (VM), `shellcheck` 0.11.0, `node` 22.23.2.*
