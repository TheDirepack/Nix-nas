# Architecture overview

NixOS NAS is designed as a single-host appliance with explicit authorities rather than a collection of overlapping management layers. NixOS installs and constrains services; upstream applications remain authoritative for their own mutable data; the NAS control plane coordinates only the operations that cross those boundaries.

## Control-plane shape

```text
                    local administrator
                           |
                     Cockpit / CLI
                           |
                    nas-cockpit-api
                           |
        +------------------+------------------+
        |                  |                  |
      setup             feature            state/
   orchestration        control            update
        |                  |                  |
        +------------ systemd / NixOS --------+

users ---> Authentik ---> Caddy authorization ---> application UIs
                    \                         \
                     \                         +--> CopyParty / Syncthing /
                      +--> capability policy        Vaultwarden / AI

KeePassXC ---> nas-secrets ---> /run/nas-secrets ---> protected services

Telegraf ---> VictoriaMetrics ---> vmalert ---> NAS alert router ---> ntfy
```

The arrows describe authority or controlled data flow, not unrestricted write access.

## Sources of truth

| Concern | Authority |
|---|---|
| Installed packages, listeners, units, sandboxes, declarative defaults | NixOS |
| Human users, credentials, MFA, groups, application access | Authentik |
| File volumes, paths, ACLs, quotas, share links, WebDAV policy | CopyParty |
| Machine secrets and encrypted-storage keys | KeePassXC |
| Application desired state | V2 `services.yaml` (mutable, seed-once from Nix, revision = sha256) |
| Application runtime topology | V2 effective-state compiler + native systemd/Podman/Caddy/Authentik/firewalld projections (finite, no daemon) |
| ZFS pool/dataset state | ZFS, with Sanoid/Syncoid for snapshot/replication policy |
| Appliance-state bundles | `nas-state` registry and signed manifests |
| Metrics | Telegraf + VictoriaMetrics |
| Alert rule evaluation/routing | vmalert + NAS alert router |

A new feature should extend an existing authority whenever possible. It should not create a second user database, share database, secret store, feature-state file, or authorization policy simply because that representation is convenient locally.

## Authentication and authorization

Authentik authenticates users and owns group membership. Caddy removes client-supplied identity headers, performs forward authentication, and applies generated capability checks at the edge. Applications keep their own native authorization where applicable. Browser visibility is convenience only; server-side policy is the security boundary.

Capability definitions come from V2 `application.<service>.<capability>` objects (ensured by `nas_v2_authentik.py`, never assigned by V2) and fail closed when a protected route references an unknown capability. Caddy strips forged `Remote-*` / `X-Authentik-*` headers, forward-authenticates to Authentik, then checks `X-Authentik-Groups` for `nas_admin` or `application.<service>.<capability>`.

## Locked boot and secrets

The machine can boot before KeePassXC is unlocked. Cockpit and the local PAM administrator form the recovery plane. `nas-secrets` reads the KDBX password from standard input, stages only required runtime material under `/run/nas-secrets`, validates storage/secrets, and then starts the protected target.

No long-running service should need broad read access to the whole secret tree when an exact credential or read-only path is sufficient.

## Mutable state and recovery

Mutable application state remains with the owning service. `nas-state` exports a versioned, signed bundle according to the state-authority registry, quiesces writers where required, validates/diffs before restore, and retains rollback material. This is coordinated recovery, not a substitute for native application consistency mechanisms.

ZFS snapshots/replication and Restic cover different failure domains; neither should be described as universally replacing the other.

## Privilege boundaries

Most long-running helpers should be unprivileged and hardened with systemd. Root is reserved for operations that actually require storage, ownership, service-control, Nix activation, or similar host authority. See [privileged-service audit](root-service-audit.md).

## Observability

Telegraf is the single host collector and writes directly to single-node VictoriaMetrics. Grafana is optional. vmalert evaluates rules against VictoriaMetrics and sends notifications to the small NAS alert router, which performs bounded deduplication/inhibition and optional ntfy delivery.

The design intentionally avoids a Prometheus server, Alertmanager, mandatory Loki, or a service mesh on this resource-conscious single-host appliance.

## Where to make changes

Use [code-map.md](code-map.md) for concrete files and [invariants.md](invariants.md) for rules that must survive refactoring.
