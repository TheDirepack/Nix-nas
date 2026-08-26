# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.1.1 — 2026-08-25

### Added

- Hardened standalone first-run setup with a disposable bootstrap KDBX/AuthentiK trust domain and a separately generated permanent, user-password-protected KDBX.
- Shared human-password strength checks using zxcvbn, HIBP range queries, Authentik-native password policy, and Linux libpwquality/PAM enforcement.
- Security regression coverage for bootstrap retirement, Caddy identity-header trust, first-run capabilities, root/ZFS storage boundaries, native ZFS key handling, firewall projection, Quadlet sources, and backup recovery domains.

### Changed

- Permanent Authentik, PostgreSQL, KeePassXC, Caddy, unlock/control-plane state, and the live Managed Services V2 `services.yaml` authority remain on the root filesystem so first-run policy is available before user storage exists; encrypted ZFS holds V2 transaction history plus declared application/storage data.
- Bootstrap secrets are never promoted into the permanent trust domain; permanent service secrets and the native OpenZFS key are regenerated during setup.
- Authentik steady-state automation is reduced to read-only identity projection permissions, with setup-only mutations isolated behind temporary bootstrap authority and native blueprints.
- Root/control-plane recovery uses Restic while complete encrypted ZFS replication preserves native ZFS encryption.
- Removed custom ZFS key fingerprints and the standalone custom Authentik proxy outpost in favor of native OpenZFS validation and Authentik's embedded outpost.

### Fixed

- First-run can no longer take over an existing Linux account, and bootstrap retirement fails closed.
- Setup no longer persists a cheap password-derived verifier for the KeePass master password.
- Authentik bearer requests refuse redirects/origin changes and redact sensitive error payloads.
- Caddy strips spoofable identity headers before reconstructing trusted Authentik identity headers.
- Managed Services V2 desired-state seeding no longer depends on the ZFS mount it helps first-run configure.

## 0.1.0 — 2026-08-25

### Added

- Consolidated appliance baseline: ZFS pools/datasets, CopyParty file sharing, Authentik identity and capability groups, Caddy forward-auth and landing portal, Cockpit host management, KeePassXC-backed secrets with locked-boot recovery, Syncthing user-device reconciliation, VictoriaMetrics/Telegraf/vmalert observability, and Restic/Syncoid backup paths.
- Managed Services V2: single `services.yaml` authority, `managed-services-v3.schema.json` contract, finite compilation into native systemd, Podman/Quadlet/Compose, libvirt, Caddy, Authentik, and firewalld, with seed-once bootstrap and transactional apply.
- Pi coding-agent integration as a transient `nas-code-agent` sandbox (workspace-allowlisted `nas-code` launcher, llama-swap as the sole model/provider authority, per-session credential isolation).
- Cockpit React/PatternFly 6 interface with Modular pages/components/hooks, schema-driven editor, and fixed privileged API allow-list.

### Changed

- Established `0.1.0` as the canonical SemVer baseline; previous `2.2.0-alpha.x` history has been archived in git history.
- Documentation audit: removed obsolete bootstrap plan and stale Pi design draft, corrected `code-map.md` to match the current module/service layout, aligned `SECURITY.md` locked-state boundary with ADR-0001 (out-of-band recovery only), and trimmed supporting records to one explanation per concern.
- Build/validation: made `validate-structure.py` ignore `.opencode` and other ignored cache directories so local agent artifacts do not fail preflight.

### Fixed

- Preflight now passes on hosts with `.opencode/node_modules` present.
- Security docs no longer claim browser Cockpit recovery while locked.