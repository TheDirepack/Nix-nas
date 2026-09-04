# Administrator configuration

`nas_admin` is the trusted appliance-superuser group. Administrative configuration is split by authority:

- **Cockpit:** appliance status, feature policy, ZFS, services, networking, updates, schedules, and searchable help.
- **Authentik:** users, groups, MFA, application/provider policy, user attributes, application bindings, and superuser accounts.
- **CopyParty:** mutable volumes, paths, ACLs, flags, quotas, indexes, and share links.
- **Syncthing:** global device/folder inspection and advanced settings.
- **`local.nix`:** installation-specific declarative options.

## Installation checklist

The step-by-step walkthrough, including this checklist with every item explained, is in [Install and set up](installation.md). All checklist items there must be complete before setting `nas.installationReady = true`.

## Important option behavior

The base NAS module keeps optional applications disabled. Import the focused profiles under `modules/profiles/` for `core-storage`, `identity-sharing`, `observability`, `virtualization`, or `local-ai`; the shipped `local.nix` demonstrates an explicit profile selection. The appliance release currently supports only `x86_64-linux`.

- Empty AI and virtualization storage roots use their ZFS defaults.
- `hardware.cpuVendor = "auto"` selects the portable profile. GPU vendors and the llama.cpp backend must match installed hardware and architecture.
- The model downloader stays disabled until immutable image digests are populated or a native package replaces it.
- Native ZFS encryption stores its key in KeePassXC and stages it under `/run` only while unlocked.
- Syncthing is LAN-oriented by default. User devices are managed through Authentik; the global Syncthing interface remains administrative.
- Vaultwarden defaults to OIDC-only sign-in. Disable that restriction only for a documented client-compatibility requirement.
- TFTP is anonymous and disabled by default. Enabling writes is appropriate only on an isolated provisioning network.
- The NUT monitor password must be readable at boot because UPS shutdown cannot depend on KeePassXC activation.
- `autoUpdate.apply = false` fetches and validates reviewed revisions without deploying them automatically.
- Same-pool Restic requires `backup.allowSamePoolRepository = true` and is local rollback only. Production readiness requires an external Restic repository or enabled ZFS replication.
- `backup.restoreVerification` controls the scheduled isolated restore test and must point to disk-backed scratch storage outside `/run`.

See the focused networking, storage, backup, CopyParty, and virtualization/AI/power pages for operational details.
