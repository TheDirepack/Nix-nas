# NixOS NAS 2.2.0-alpha.17

A NixOS-based NAS appliance that keeps storage, identity, secrets, applications, and recovery paths explicit and independently understandable.

The core stack is ZFS + CopyParty + Authentik + Cockpit + KeePassXC-backed secrets, with optional Syncthing, Vaultwarden, virtualization, local AI, and a lightweight VictoriaMetrics/Telegraf observability stack.

> **Release status:** 2.2.0-alpha.17 is a source-only development artifact until its exact Cockpit frontend, Nix closures, VM tests, installer path, and hardware recovery drills are qualified. Do not treat a source-only archive as an install-ready appliance image.

## First installation

1. Replace `hardware-configuration.nix` with reviewed output from the target machine.
2. Review `local.nix` and complete the installation checklist in [`docs/src/admin/configuration.md`](docs/src/admin/configuration.md).
3. Copy `setup/first-run.example.json` to the configured first-run path and fill in the initial accounts, storage plan, and feature policy.
4. Run the fast source checks:

   ```bash
   ./scripts/preflight.sh
   ```

5. Build or install the NixOS configuration. `nas-first-start.service` validates the first-start plan automatically.
6. Open Cockpit at `https://<host>.local:9092/console/`. The NAS page guides first-start setup and, after reboot, locked-state unlock.
7. Confirm any new-pool operation separately. Storage creation is intentionally never hidden behind a generic setup confirmation.

For the exact setup flow, see [`docs/src/admin/first-run.md`](docs/src/admin/first-run.md).

## Day-to-day administration

Use the interface that owns the setting instead of maintaining duplicate configuration:

| Task | Use |
|---|---|
| Appliance status, service policy, ZFS actions, updates, schedules, diagnostics | Cockpit |
| Users, passwords, MFA, groups, application access | Authentik |
| File volumes, ACLs, quotas, share links, WebDAV policy | CopyParty |
| Machine secrets and encrypted-storage unlock material | KeePassXC + `nas-secrets` |
| Per-user sync declarations | Authentik settings; reconciled into Syncthing |
| Advanced Syncthing inspection | Syncthing admin UI |
| Metrics and dashboards | VictoriaMetrics + optional Grafana |
| Declarative installation and service wiring | NixOS |

The complete authority map is in [`docs/src/admin/service-map.md`](docs/src/admin/service-map.md).

## Recovery model

Protected services stay stopped until secrets and storage checks succeed. Cockpit and the local PAM administrator remain available as the cold-boot recovery plane. Mutable appliance state can be exported, validated, compared, and restored with `nas-state`, while ZFS snapshots/replication and Restic cover different recovery layers.

Keep an offline copy of the recovery material listed in [`docs/operator/recovery.md`](docs/operator/recovery.md).

## Documentation

- **Operator manual:** [`docs/src/`](docs/src/README.md) — installed into Cockpit and organized by task.
- **Recovery runbook:** [`docs/operator/recovery.md`](docs/operator/recovery.md) — long-form disaster recovery.
- **Security model:** [`SECURITY.md`](SECURITY.md) — trust and privilege boundaries.
- **Contributor guide:** [`CONTRIBUTING.md`](CONTRIBUTING.md) — development workflow and quality gates.
- **Agent handoff:** [`AGENTS.md`](AGENTS.md) — compact reading order for coding agents.
- **Development internals:** [`docs/development/`](docs/development/README.md) — architecture, tests, risks, and validation evidence.

## Validation

Fast source/security/fuzz matrix:

```bash
./scripts/test-matrix.py fast --report test-evidence/fast.json
```

The lower-level source preflight remains available as `./scripts/preflight.sh`. To see which heavyweight tiers are runnable on the current host, use `./scripts/test-matrix.py list`.

Full NixOS/QEMU validation on a capable Linux builder:

```bash
nix develop .#qemu-test -c ./scripts/qemu-test.sh all
```

An install-ready release additionally requires the evidence in [`docs/development/release-checklist.md`](docs/development/release-checklist.md).
