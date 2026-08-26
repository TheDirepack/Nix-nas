# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
