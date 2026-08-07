# Administrator configuration

`nas_admin` is the trusted appliance-superuser group. Administrative configuration is split by authority:

- **Cockpit:** appliance status, feature policy, ZFS, services, networking, updates, schedules, and searchable help.
- **Authentik:** users, groups, MFA, application/provider policy, user attributes, application bindings, and superuser accounts.
- **CopyParty:** mutable volumes, paths, ACLs, flags, quotas, indexes, and share links.
- **Syncthing:** global device/folder inspection and advanced settings.
- **`local.nix`:** installation-specific declarative options.

## Installation checklist

Complete these values before setting `nas.installationReady = true`:

1. Replace `hardware-configuration.nix` with reviewed `nixos-generate-config` output.
2. Set a stable eight-character `networking.hostId`, record it with recovery material, and do not change it after pool creation or import.
3. Configure the boot loader for the installed firmware and partitions.
4. Install at least one administrator SSH public key and a root-only password-hash file for local Cockpit/PAM access.
5. Set the trusted network interfaces.
6. Verify `zfsPool`, `zfsDataset`, `zfsRoot`, and the intended boot-import policy.
7. Run `./scripts/preflight.sh` and the QEMU suite before deployment.

A stable host ID can be derived once with:

```console
head -c 8 /etc/machine-id
```

For UEFI installations, enable systemd-boot only after confirming the EFI System Partition in `hardware-configuration.nix`. Configure GRUB instead when the target installation requires it.

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
