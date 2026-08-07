# Decision history

This is intentionally a summary, not an audit transcript.

## Current architecture

The project converged on Authentik for identity, CopyParty for share authority, KeePassXC for machine secrets, Caddy for forward-auth routing and the landing page, Cockpit for host management, Syncthing for synchronization, and VictoriaMetrics/Grafana for observability. Custom portal, user-settings, generated CopyParty ACL, LLDAP, Authelia, Apprise, and desktop D-Bus secret paths were removed.

## Alpha.10–11

- Established explicit `nas_allow_*` capability groups and default-deny access.
- Made `nas_admin` the only Authentik superuser group while permitting multiple explicitly trusted administrators.
- Kept cold-boot Cockpit/PAM authority separate from Authentik authority.
- Moved user-editable Syncthing devices into Authentik and restricted reconciliation to reserved objects.
- Separated vmalert/Alertmanager operation from optional ntfy delivery.

## Alpha.12

- Fixed NixOS 26.05 evaluation/build blockers and the Cockpit-ZFS Node 24/Yarn issue by using Node 22 with rebuilt Yarn Berry.
- Added native full-stack and encrypted-ZFS NixOS tests plus an official-ISO install/reboot harness.
- Added live authorization, service lifecycle, ZFS restore, TFTP, secret rollback, and application checks.

## Alpha.13

- Added idempotent `nas-setup` first-run orchestration and runtime account commands.
- Added secure password-file/stdin handling, guarded multi-disk pool creation, account population, personal-directory provisioning, feature application, and last-administrator protection.

## Alpha.14

- Split Nix internal context into base, feature catalog, and Caddy helper files.
- Added duplicate-export detection and a feature-catalog JSON Schema.
- Batched systemd queries, consolidated common subprocess parsing, expanded Cockpit/JavaScript tests, and changed installer VMs to ephemeral key-only SSH.

## Alpha.15

- Reduced the active documentation surface to one agent guide, grouped development/runbook material, and concise history/backlog files.
- Replaced duplicated shell architecture checks with domain-organized executable contract tests and a small preflight orchestrator.
- Split documentation/Cockpit packaging away from account/runtime command packaging.
- Corrected the generated source-document reference from nonexistent `storage-tools.nix` to `zfs-tools.nix`.

## Alpha.16

- Removed code narration and historical comments, moved durable rationale into operator/development documentation, and added tests for the comment policy.
- Replaced source-contract assertions that depended on comments with checks of actual configuration and routing behavior.

## Alpha.17

- Retired the centralized backlog after implementing its repository-addressable work and moving durable deployment and immutable-input boundaries into focused development documents.
- Split the largest service entry points into stable command surfaces plus reusable feature, identity, and setup modules.
- Added fault-injected secret-transaction tests, a complete browser authorization matrix, and executable external validation drills for boot, sharing, replication, backup, identity, and observability.
- Kept CopyParty and HuggingFaceModelDownloader changes behind verifiable immutable-input policy instead of editing nested locks or shipping placeholder hashes.
## Alpha.18

- Reconciled the older Alpha.14 review against the current implementation and fixed the remaining release blockers rather than reapplying already-resolved structural findings.
- Added rollback-safe feature transactions, bounded/deprivileged wake handling, scoped routine Authentik automation authority, explicit appliance profiles, a versioned mutable-state bundle, and isolated backup restore verification.
- Made release evidence explicit: source-only validation is marked partial, complete publication requires Nix/lint evidence, and archive/checksum/manifest/provenance are published atomically.


## Alpha.24

- Added one generated capability/group registry consumed by Nix, Caddy, Python policy, setup exports, documentation, and contract tests; unknown Caddy capabilities now fail evaluation.
- Consolidated Ruff and Pyright settings in `pyproject.toml`, made Cockpit CI lockfile-only, retained the exact built bundle, and added an unprivileged unit-test job.
- Removed the Prometheus server, exporter services, Alertmanager, notification bridge, and unused Authentik metrics listener. Telegraf now writes host, ZFS, SMART, systemd, and optional UPS metrics directly to VictoriaMetrics; Grafana uses the native VictoriaMetrics datasource plugin; vmalert sends to a hardened dedicated-user NAS router with optional direct ntfy delivery.
- Began shared structured operation logging with bounded redaction and applied it to the alert-routing boundary.

## Alpha.25

The documentation and operator experience were normalized around task-oriented navigation and clear authority ownership. Cockpit wording was simplified without changing its privilege model, runtime account administration was separated from first-start instructions, contributor architecture/release guides were added, and `nas-doctor` began showing remediation guidance in human-readable output.
