# Privileged-service audit

This is a living audit of custom units. It records the required privilege boundary rather than assuming every appliance helper must run as root.

| Unit or class | Runtime identity | Why privilege is needed | Current boundary | Follow-up |
|---|---|---|---|---|
| `nas-alert-router.service` | `nas-observability` | None | Dedicated user, strict filesystem protection, empty capability set, bounded read-only secret mounts | Keep unprivileged. |
| `telegraf.service` | `telegraf` | SMART device interrogation only | Exact Nix-store `smartctl` command through `NOPASSWD:NOSETENV`; all other collection remains unprivileged | VM-test SMART access and assert the exact sudo command. |
| ZFS create/unlock/import/restore helpers | root | Dataset, key, mount, snapshot, and block-device operations | Fixed Nix-store executables, guarded inputs, systemd isolation, operation journals | Split preparation from long-running work wherever a helper remains resident. |
| Setup/update/state restore entry points | root | NixOS activation, account setup, state ownership, service control | Fixed command allow-lists, operation locks/journals, bounded subprocess execution | Add generated assertions for writable paths and capabilities per unit. |
| Identity and Syncthing reconciliation | Mixed; some root orchestration | Writes generated state and service-owned configuration | Transaction plans and service-specific ownership | Continue moving network reconciliation into dedicated users with narrowly staged root file installation. |

## Rules for new units

1. Default to a dedicated static or dynamic user.
2. Declare `StateDirectory`, `RuntimeDirectory`, or `CacheDirectory` instead of creating broad writable trees.
3. Use systemd credentials or exact read-only secret mounts.
4. Set `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, an empty capability set, and restricted address families unless the documented operation requires an exception.
5. Treat every exception—especially device access, sudo, writable paths, and namespace access—as a tested contract.
