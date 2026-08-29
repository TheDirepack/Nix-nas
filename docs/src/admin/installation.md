# Install and set up your NAS

This walkthrough takes a competent Linux administrator from a blank machine to a working NAS without assuming prior NixOS or ZFS fluency. Jargon is explained where it first appears, and deep mechanics stay in the linked pages.

## What you will end up with

A NAS that boots **locked** and stays that way until you enter a KeePass database password. Unlocking starts the protected stack (Cockpit for administration, Authentik for sign-in, CopyParty for files), reached through the browser over HTTPS. Your ZFS storage pool is created only during guided setup, so no disk is ever formatted behind your back.

## Before you begin

Have everything on this list before starting:

- An `x86_64-linux` machine (the appliance release currently supports only this architecture).
- A boot disk for the operating system plus separate data disks for storage.
- LAN access to the machine.
- A NixOS installer USB matching the machine firmware. UEFI firmware uses systemd-boot; BIOS installs use GRUB instead.
- This repository checked out on the target machine.
- An administrator SSH public key.
- Chosen usernames and passwords for the administrator and initial users.
- Somewhere offline, such as paper or an encrypted note, to record recovery material.

## The process at a glance

1. [Configure the host](#phase-1-configure-the-host): generate hardware configuration, edit `local.nix`.
2. [Build and install NixOS](#phase-2-build-and-install-nixos): format the OS disk, install the `.#nas` configuration.
3. [Prepare the first-run plan](#phase-3-prepare-the-first-run-plan): fill in accounts and the storage plan.
4. [Complete guided setup](#phase-4-complete-guided-setup): browser wizard or CLI.
5. [Verify and record](#phase-5-verify-and-record): unlock, harden tokens, write down recovery material.

## Phase 1: Configure the host

The repository ships a template configuration. You tailor two files to your hardware before installing anything.

### Generate the hardware configuration

On the target machine, run `nixos-generate-config`, review its output, and replace the shipped `hardware-configuration.nix` in the repository with the reviewed result. This file tells NixOS about your disks and filesystems; do not skip reviewing it.

### Edit `local.nix`

`local.nix` holds the installation-specific settings. Work through these items:

1. **Set `networking.hostId`.** The shipped value is the placeholder `00000000`. A host ID is an eight-character identifier NixOS uses to identify the machine to ZFS. Derive it once from the target machine:

   ```console
   head -c 8 /etc/machine-id
   ```

   Write the value down with your recovery material. It must never change after the pool is created or imported.

2. **Add your SSH public key** to `users.users.admin.openssh.authorizedKeys.keys`. The shipped file leaves this list empty, which means no SSH access until you add a key.

3. **Set `nas.trustedInterfaces`** to the names of your LAN interfaces (for example `[ "enp1s0" ]`). These are the only interfaces allowed to reach SSH, HTTPS, mDNS, Syncthing, and optional TFTP; empty is fail-closed.

4. **Pick feature profiles.** The optional applications stay disabled unless you import their profiles from `modules/profiles/`: `core-storage`, `identity-sharing`, `observability`, `virtualization`, `local-ai`. The shipped `local.nix` shows an explicit selection.

5. **Review the storage names**: `nas.zfsPool`, `nas.zfsDataset`, `nas.zfsRoot` (shipped defaults: `tank`, `tank/nas`, `/tank`) and the boot-import policy (`nas.zfsImportAtBoot`).

6. **Create the administrator password-hash file.** `nas.adminPasswordHashFile` points to a root-only file containing a Linux password hash for local Cockpit/PAM sign-in. Shipped path:

   ```bash
   sudo install -m 0600 /dev/null /etc/nixos/nixos-nas/secrets/admin-password-hash
   ```

   Place a hash of your chosen password in that file, for example generated with `mkpasswd -m sha-512`.

7. **Configure the boot loader for your firmware.** For UEFI, enable systemd-boot only after confirming the EFI System Partition appears in `hardware-configuration.nix`; use GRUB when the machine requires it.

### Finish the host preparation

Complete every item in the installation checklist in [Administrator configuration](configuration.md). Then set `nas.installationReady = true`: this enables strict readiness assertions covering hardware, SSH, network, and ZFS setup, including that the pool imports at boot and that a recovery target exists (an off-pool Restic repository or enabled ZFS replication).

Run the fast source checks:

```bash
./scripts/preflight.sh
```

Before deploying, also run the full NixOS/QEMU suite shown in the [Operator command index](../../operator/operations.md); it requires Linux, Nix, QEMU/KVM, and network access.

## Phase 2: Build and install NixOS

A *flake* is a reproducible Nix entry point; `flake.nix` defines the NixOS configurations this repository can build. `.#nas` means "the configuration named `nas` in this repository".

1. Boot the NixOS installer USB.
2. Partition and format **only the OS disk**, using the reviewed example in `installation/disko-os-disk-example.nix`. [Disko](storage-recovery.md) is a declarative NixOS disk-partitioning tool; its examples are destructive and erase the disks they name. Before running anything: replace placeholders with stable `/dev/disk/by-id/...` paths, confirm each identifier resolves to the expected physical disk, inspect the generated commands, and back up all recoverable data. The pool-layout worksheet in `installation/pool-layout.md` helps you record the intended layout.
3. Install the flake configuration targeting `.#nas` from the repository checkout, following standard NixOS installer tooling.
4. Reboot into the installed system.

The data pool itself is **not** created during installation. It is created during guided setup so that pool creation stays explicit and separately confirmed.

## Phase 3: Prepare the first-run plan

Use the local console, SSH with the key you provisioned, or hardware KVM. The *first-run plan* is a JSON file describing the initial accounts, storage, and feature modes.

1. Copy `setup/first-run.example.json` to the configured first-run path. The shipped default is `/etc/nixos/nixos-nas/first-run.json` (the `nas.firstStart.configFile` option). Edit the copy outside the Nix store: accounts, storage plan, and feature modes.

2. Passwords never go into the JSON. Each account references a private password file instead:

   ```bash
   install -m 0600 /dev/null /run/keys/nas-alice-password
   read -r -s -p 'Alice password: ' password
   printf '%s\n' "$password" > /run/keys/nas-alice-password
   unset password
   ```

   Setup rejects password files readable by group or other users, rejects symlinks, and opens each file exactly once.

3. Validate the plan before making changes:

   ```bash
   nas-setup validate-config /etc/nixos/nixos-nas/first-run.json
   ```

4. Publish and review the ready state:

   ```bash
   nas-setup prepare-first-start --config /etc/nixos/nixos-nas/first-run.json
   ```

   Review the published `ready` state: the exact pool name, devices, topology, and plan digest. Setup never acts on a plan you have not seen in this form.

### Choosing the storage plan

When the plan creates a new pool, choose a topology: `single`, `stripe`, `mirror`, `raidz1`, `raidz2`, or `raidz3`. A *mirror* keeps full copies of data on each member disk; the raidz levels trade capacity for parity redundancy. Always use stable `/dev/disk/by-id/...` paths rather than `/dev/sdX` names. The CLI applies safe defaults (`ashift=12`, `compression=zstd`) described in [First start](first-run.md).

Example mirror configuration:

```json
{
  "storage": {
    "createPool": true,
    "devices": [
      "/dev/disk/by-id/ata-EXACT_DISK_0",
      "/dev/disk/by-id/ata-EXACT_DISK_1"
    ],
    "topology": "mirror",
    "wipeDevices": true,
    "ashift": 12
  }
}
```

## Phase 4: Complete guided setup

Two routes reach the same result. Run either as the configured local administrator, not as root.

### Route A: the browser wizard

Open `https://<nas-hostname>.local/setup/` and follow the first-start wizard: administrator account, storage plan review, and final confirmation. Configure the host locale declaratively in NixOS; the wizard does not maintain a second mutable locale setting.

Authentik gates the wizard. Sign in with its temporary bootstrap identity `akadmin` and the documented initial password `nas-admin-first-boot`. This identity exists only for initial setup; setup retires it automatically once your own administrator account has been created and verified. Protected applications stay unavailable until setup completes and the system unlocks.

### Route B: the CLI from a recovery terminal

From the local console, SSH session, or KVM terminal:

```bash
status_json="$(nas-setup prepare-first-start --config /etc/nixos/nixos-nas/first-run.json)"
plan_digest="$(printf '%s' "$status_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["planDigest"])')"
nas-setup first-run \
  --config /etc/nixos/nixos-nas/first-run.json \
  --confirm-plan-digest "$plan_digest"
```

When creating a new pool, repeat `--confirm-storage-device` once per configured disk and pass `--allow-destructive-storage`:

```bash
nas-setup first-run \
  --config /etc/nixos/nixos-nas/first-run.json \
  --confirm-storage-device /dev/disk/by-id/ata-EXACT_DISK_0 \
  --confirm-storage-device /dev/disk/by-id/ata-EXACT_DISK_1 \
  --confirm-plan-digest "$plan_digest" \
  --allow-destructive-storage
```

The destructive flag is required even when wiping is disabled, because creating a pool writes ZFS labels. Setup prompts once for the KeePass database password, is resumable if interrupted, and never silently creates pools. The full stage order and automation options are in [First start](first-run.md).

## Phase 5: Verify and record

Everything below happens after setup completes and the system reboots.

1. **Reboot and unlock.** Locked boot is normal behavior. Unlock through the normal flow in [Locked-state unlock](../locked-unlock.md):

   ```bash
   sudo nas-secrets activate
   ```

2. **Sign in through the browser.** Use Authentik via Caddy at `https://<nas-hostname>.local/console/` with the administrator account created during setup; do not use the retired `akadmin` identity.

3. **Harden the Authentik API token.** The runtime token still equals the bootstrap token at this point. Create a narrower service-account token in Authentik and store it with `nas-secrets set-authentik-token`. Complete this before production use.

4. **Enable backups deliberately.** Same-pool Restic requires `backup.allowSamePoolRepository = true` and is rollback protection only. Production readiness requires an external Restic repository or enabled ZFS replication, which the readiness assertions from Phase 1 already enforce.

5. **Record recovery material offline.** Keep the list in the [Recovery runbook](../../operator/recovery.md): host ID, `/dev/disk/by-id/...` paths, exact pool topology, KeePassXC database location and an independent copy of its password, backup snapshot IDs, and Authentik recovery material. Update it after every storage or identity change, and perform a quarterly restore drill against disposable media or a VM.

## Where to go next

- [Administrator configuration](configuration.md) — option behavior notes for AI, encryption, Syncthing, backups, and more.
- [First start](first-run.md) — the complete setup-state reference, commands, and safeguards.
- [Storage installation and recovery](storage-recovery.md) — Disko examples and the rules to follow before formatting anything.
- [Locked-state unlock](../locked-unlock.md) — the everyday unlock transaction.
- [Configuration and management map](admin/service-map.md) — which interface owns which setting.
- [Operator command index](../../operator/operations.md) — console commands for maintenance.
- [Recovery runbook](../../operator/recovery.md) — what to do when something breaks.

## If something goes wrong

Protected services stay stopped until secrets and storage checks succeed; this is intentional. There is no browser recovery path while the system is locked. Recover from the local console, SSH with a provisioned recovery key, or hardware KVM using `sudo nas-secrets activate`, then follow the [Recovery runbook](../../operator/recovery.md) if the failure persists.
