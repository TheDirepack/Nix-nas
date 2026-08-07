# NixOS NAS manual

This manual is installed with the NAS Cockpit package. It is organized around the task you are performing rather than the implementation language behind it.

## What do you need to do?

| Goal | Start here |
|---|---|
| Install or finish first-start setup | [Administrator configuration](admin/configuration.md) → [First start](admin/first-run.md) |
| Unlock the NAS after boot | [Locked-state unlock](locked-unlock.md) |
| Add, disable, or change user access | [Accounts and access](admin/accounts.md) → [Permission model](permissions.md) |
| Manage files, shares, ACLs, or WebDAV | [CopyParty](admin/copyparty.md) |
| Manage personal synchronization | [Syncthing](admin/syncthing.md) |
| Check storage, snapshots, replication, or backups | [Storage and recovery](admin/storage-recovery.md) → [Backups](admin/backups.md) |
| Change service power/runtime policy | [Maintenance and service policy](admin/maintenance.md) |
| Check alerts, metrics, or dashboards | [Observability and alerts](admin/observability.md) |
| Find the right UI for a setting | [Configuration and management map](admin/service-map.md) |
| Recover from a serious failure | [Recovery runbook](reference/project-RECOVERY.md) |
| Find an exact command, option, path, or endpoint | [Reference](reference/commands.md) and full-text search |

## If you are a normal user

Start with [Applications](users/applications.md) and [User settings](users/settings.md). Administrative Cockpit pages are not intended to replace application-specific user interfaces.

## A simple ownership rule

Configure each thing where it is authoritative:

- **Authentik:** identities, passwords, MFA, groups, and application access.
- **CopyParty:** file volumes, paths, ACLs, quotas, flags, and share links.
- **Cockpit:** appliance status, reviewed host operations, service policies, and recovery entry points.
- **NixOS:** installed software, listeners, units, sandboxes, and declarative defaults.
- **KeePassXC + `nas-secrets`:** machine secrets and unlock material.
- **ZFS/Sanoid/Syncoid/Restic:** storage state and the appropriate snapshot/replication/backup layer.
- **Telegraf + VictoriaMetrics + vmalert:** metrics collection, history, and alert evaluation.

When unsure, use [Configuration and management map](admin/service-map.md) before creating duplicate configuration elsewhere.

Generated reference pages are rebuilt with the deployed Nix generation. Do not edit generated pages as configuration.
