# Administrator configuration

`nas_admin` is the trusted appliance-superuser group. Administrative configuration is split by authority:

- **Cockpit:** appliance status, feature policy, ZFS, services, networking, updates, schedules, and searchable help.
- **Authentik:** users, groups, MFA, application/provider policy, user attributes, application bindings, and superuser accounts.
- **CopyParty:** mutable volumes, paths, ACLs, flags, quotas, indexes, and share links.
- **Syncthing:** global device/folder inspection and advanced settings.
- **`local.nix`:** installation-specific declarative options.

## Installation checklist

Complete these values before setting `nas.installationReady = true`:

1. Replace the repository `hardware-configuration.nix` placeholder with reviewed `nixos-generate-config` output from the actual target host. The placeholder carries an internal stub marker and install-ready evaluation fails while it is present.
2. Set a stable eight-character `networking.hostId`, record it with recovery material, and do not change it after pool creation or import. `00000000` and the historical example IDs are rejected for install-ready systems.
3. Configure the boot loader for the installed firmware and partitions.
4. Configure and test a recovery path. Either declare an SSH authorized key on a user that is in `nas-administrators`, or verify a local console/out-of-band KVM path and set `nas.recovery.consoleOrKvmAvailable = true`.
5. Set `nas.trustedInterfaces` to the real LAN interfaces. An empty list remains fail-closed and is rejected for install-ready deployments.
6. Verify `zfsPool`, `zfsDataset`, `zfsRoot`, and the intended boot-import policy. Prefer native ZFS encryption. If encryption is deliberately disabled, review the security warning and set `nas.zfsEncryption.disabledAcknowledged = true`; install-ready evaluation otherwise fails.
7. Verify required KeePass/bootstrap/backup credential files are regular files with restrictive ownership and permissions. The runtime secret-file preflight rejects symlinks, unsafe ownership, and broad modes before identity/protected runtime activation.
8. Run `./scripts/preflight.sh` and the QEMU suite before deployment.

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
- Native ZFS encryption stores its key in KeePassXC and stages it under `/run` only while unlocked. Disabling native encryption emits a prominent security warning, and an install-ready deployment requires `nas.zfsEncryption.disabledAcknowledged = true` if encryption remains off.
- `nas.recovery.consoleOrKvmAvailable` is an explicit operator attestation, not an automatic probe. Set it only after verifying the real console/KVM recovery path on the target machine.
- Syncthing is LAN-oriented by default. User devices are managed through Authentik; the global Syncthing interface remains administrative.
- Vaultwarden defaults to OIDC-only sign-in. Disable that restriction only for a documented client-compatibility requirement.
- TFTP is anonymous and disabled by default. Enabling writes is appropriate only on an isolated provisioning network.
- The NUT monitor password must be readable at boot because UPS shutdown cannot depend on KeePassXC activation.
- `autoUpdate.apply = false` fetches and validates reviewed revisions without deploying them automatically.
- Same-pool Restic requires `backup.allowSamePoolRepository = true` and is local rollback only. Production readiness requires an external Restic repository or enabled ZFS replication.
- `backup.restoreVerification` controls the scheduled isolated restore test and must point to disk-backed scratch storage outside `/run`.

See the focused networking, storage, backup, CopyParty, and virtualization/AI/power pages for operational details.
