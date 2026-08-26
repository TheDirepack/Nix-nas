# Decision history

This is intentionally a summary, not an audit transcript. Detailed per-release prose now lives in `CHANGELOG.md` and git history; this file records only durable architectural direction.

## Current architecture

The project converged on Authentik for identity, CopyParty for share authority, KeePassXC for machine secrets, Caddy for forward-auth routing and the landing page, Cockpit for host management, Syncthing for synchronization, and VictoriaMetrics/Grafana for observability. Custom portal, user-settings, generated CopyParty ACL, LLDAP, Authelia, Apprise, and desktop D-Bus secret paths were removed.

Managed Services V2 is the single application-definition layer: `services.yaml` (mutable, seed-once) + `managed-services-v3.schema.json` (structural/UI contract) compiled finitely into native systemd, Podman/Quadlet/Compose, libvirt, Caddy, Authentik capability objects, and firewalld. `features.json` and the `nas-feature-control` gate/controller are gone. Caddy is the sole HTTPS front door (bootstrap static guidance pre-secrets, Authentik-gated routes after activation). The Pi coding-agent runs as a transient `nas-code-agent` sandbox with llama-swap as the sole model/provider authority.

## Baseline 0.1.0 — 2026-08-25

- Reset versioning from the `2.2.0-alpha.x` line to `0.1.0` as a clean SemVer baseline. Full alpha history remains in `git log` and archived `CHANGELOG.md` entries prior to this reset.
- Audited and consolidated documentation: removed the superseded `caddy-first-boot-bootstrap-plan.md` and the stale `pi-coding-agent-architecture.md` draft, corrected `code-map.md` for the current Nix module and Python service layout, and aligned `SECURITY.md` with ADR-0001's out-of-band locked-boot recovery.
- Retained durable invariants (NixOS as package/unit authority, Authentik as identity authority, KeePassXC as secret authority, etc.) unchanged.
