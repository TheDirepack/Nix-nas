# NixOS NAS 0.1.0

NixOS NAS is a NixOS-based NAS appliance that keeps storage, identity, secrets, applications, and recovery paths explicit and independently understandable: each setting is owned by exactly one interface. The core stack is ZFS + CopyParty + Authentik + Cockpit + KeePassXC-backed secrets.

## Features

- ZFS pool management with snapshots and replication (Sanoid/Syncoid), plus Restic backups.
- Single sign-on with MFA through Authentik.
- File sharing with volumes, ACLs, quotas, share links, and WebDAV through CopyParty.
- Web administration through Cockpit, including guided first-start setup and locked-boot unlock.
- Machine secrets in a KeePassXC database, staged under `/run` only while the system is unlocked.
- Optional Syncthing, Vaultwarden, virtualization, local AI, and a VictoriaMetrics/Telegraf observability stack.
- Recovery-first design: a cold-boot Cockpit/PAM recovery plane, `nas-state` export/restore for appliance state, and Restic for backups.

**Version note:** `0.1.0` is the NixOS NAS project/release version. The `system.stateVersion = "26.05"` value in `local.nix` is the NixOS compatibility baseline for stateful module defaults; it is not the project version and must not be changed merely to match a project release.

## First installation

1. Replace `hardware-configuration.nix` with reviewed output from the target machine. The committed placeholder now rejects `nas.installationReady = true`.
2. Review `local.nix` and complete the installation checklist in [`docs/src/admin/configuration.md`](docs/src/admin/configuration.md). Before marking the host installation-ready, configure either an administrator SSH key or verify and explicitly attest a working local-console/hardware-KVM recovery path.
3. Decide whether the managed ZFS dataset will use native encryption. If encryption stays disabled, the configuration emits a prominent warning and `installationReady` requires the explicit `nas.zfsEncryption.acknowledgeUnencrypted = true` acknowledgement.
4. Copy `setup/first-run.example.json` to the configured first-run path and fill in the initial accounts, storage plan, and feature policy.
5. Run the fast source checks:

## Release status

Version 0.1.0 is a source-only development artifact. It is not an install-ready appliance image until its exact Cockpit frontend, Nix closures, VM tests, installer path, and hardware recovery drills are qualified; see [`docs/development/release-checklist.md`](docs/development/release-checklist.md).

## Getting started

6. Build or install the NixOS configuration. `nas-first-start.service` validates the first-start plan automatically.
7. Open Cockpit at `https://<host>.local:9092/console/`. The NAS page guides first-start setup and, after reboot, locked-state unlock.
8. Confirm any new-pool operation separately. Storage creation is intentionally never hidden behind a generic setup confirmation.

You should be comfortable with Linux administration; NixOS basics help but are explained as they come up.

1. Prepare the host configuration (`hardware-configuration.nix`, `local.nix`).
2. Build and install NixOS from the flake target `.#nas`.
3. Prepare the first-run plan (accounts, storage plan, feature modes).
4. Complete guided setup (browser wizard or CLI).
5. Verify the result and record your offline recovery material.

The full walkthrough is [Install and set up](docs/src/admin/installation.md).

## How the system is organized

Use the interface that owns the setting instead of maintaining duplicate configuration:

| Task | Owning interface |
|---|---|
| Appliance status, service policy, updates, reviewed host operations | Cockpit |
| Users, passwords, MFA, groups, application access | Authentik |
| File volumes, ACLs, quotas, share links, WebDAV policy | CopyParty |
| Machine secrets and encrypted-storage unlock material | KeePassXC + `nas-secrets` |
| Declarative installation and service wiring | NixOS |
| Storage state across snapshot, replication, and backup layers | ZFS + Sanoid/Syncoid + Restic |
| Metrics collection, history, and alert evaluation | Telegraf + VictoriaMetrics (+ vmalert) |

The complete authority map is in [`docs/src/admin/service-map.md`](docs/src/admin/service-map.md).

## Recovery model

Protected services stay stopped until secrets and storage checks succeed. Cockpit and the local PAM administrator remain available as the cold-boot recovery plane. Mutable appliance state can be exported, validated, compared, and restored with `nas-state`, while ZFS snapshots/replication and Restic cover different recovery layers.

Keep an offline copy of the recovery material listed in [`docs/operator/recovery.md`](docs/operator/recovery.md).

## Automatic updates

`nas.autoUpdate.enable = true` schedules the guarded update check/fetch/build workflow. It does **not** activate a new system generation unless `nas.autoUpdate.apply = true` is also set. Keeping `apply = false` is therefore a scheduled validation/check mode, not unattended updating.

## Documentation

- **Operator manual:** [`docs/src/`](docs/src/README.md) — installed into Cockpit and organized by task.
- **Installation walkthrough:** [`docs/src/admin/installation.md`](docs/src/admin/installation.md) — end-to-end install and first-start guide.
- **Recovery runbook:** [`docs/operator/recovery.md`](docs/operator/recovery.md) — long-form disaster recovery.
- **Security model:** [`SECURITY.md`](SECURITY.md) — trust and privilege boundaries.
- **Contributor guide:** [`CONTRIBUTING.md`](CONTRIBUTING.md) — development workflow and quality gates.
- **Agent handoff:** [`AGENTS.md`](AGENTS.md) — compact reading order for coding agents; operator procedures do not depend on it.
- **Development internals:** [`docs/development/`](docs/development/README.md) — architecture, tests, risks, and validation evidence.
- **Agent handoff:** [`AGENTS.md`](AGENTS.md) — compact reading order for coding agents.

## Development and validation

Development workflow, style, and release discipline are described in [`CONTRIBUTING.md`](CONTRIBUTING.md). `./scripts/preflight.sh` runs fast source checks before packaging.

Run the fast source/security/fuzz matrix:

```bash
./scripts/test-matrix.py fast --report test-evidence/fast.json
```

Run full NixOS/QEMU validation on a capable Linux builder:

```bash
nix develop .#qemu-test -c ./scripts/qemu-test.sh all
```

An install-ready release additionally requires the evidence in [`docs/development/release-checklist.md`](docs/development/release-checklist.md).
