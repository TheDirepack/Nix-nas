# QEMU test harness for the NixOS NAS

A self-contained, **no-sudo** harness that boots the NixOS minimal installer ISO
under QEMU/KVM, performs an **unattended install** into a local qcow2 disk, and
then gives you an SSH-accessible NixOS VM into which the project flake can be
copied and evaluated. There is **no `nix` binary on the host** — all Nix work
happens inside the VM.

## Prerequisites (verified on this host)

| Requirement            | Status |
|------------------------|--------|
| `qemu-system-x86_64` + `qemu-img` (v11) | on `PATH` |
| `/dev/kvm` world-writable (`crw-rw-rw-`) | KVM without root |
| NixOS minimal ISO | `QEMU_ISO` (default `/tmp/opencode/qemu/nixos-minimal-x86_64.iso`) |
| host tools | `7z`, `ssh-keygen`, `ssh`, `rsync`, `mkfs.ext4`, `truncate`, `python3` |
| RAM / disk | ~4 GiB free RAM, ~2-3 GiB disk for a 40G sparse qcow2 |

`expect` is **not** required — the serial console is driven by
`serial-console.py` (a tiny expect-style engine over QEMU's unix-socket
serial chardev). `sudo` is never used.

## How the unattended install works

1. The ISO contains a ready-made **"Serial console" ISOLINUX entry**. Instead of
   interacting with the boot menu, `run-vm.sh` *parses* that entry out of the
   ISO's `isolinux.cfg` and boots its exact kernel + initrd + kernel command
   line directly:

   ```
   -kernel  boot/nix/store/<hash>-linux-*/bzImage
   -initrd  boot/nix/store/<hash>-initrd-*/initrd
   -append  "init=/nix/store/<hash>-system-nixos/init root=fstab ... console=ttyS0,115200n8"
   ```

   The ISO is still attached as a CD-ROM, so the initrd's stage-1 mounts it by
   volume label (`nixos-minimal-26.05-x86_64`) and the live system comes up
   with a root shell on the serial console.

2. `install.sh` builds a small read-only ext4 **provisioning image**
   (`state/provisioning.img`) containing `install-live.sh` and the target
   `configuration.nix` (with the harness SSH key baked in), attaches it as
   `/dev/vdb` (target disk is `/dev/vda`), and drives the serial console:

   - wait for `login:` → log in as `root` (empty password)
   - `mount -r /dev/vdb /provision && bash /provision/install-live.sh`

3. `install-live.sh` (inside the VM) partitions `/dev/vda` (MBR +
   GRUB/BIOS — the simplest reliable boot for QEMU), formats, mounts, runs
   `nixos-generate-config`, writes `configuration.nix`, and runs
   `nixos-install --no-root-passwd`. It finishes by echoing `INSTALL_COMPLETE`
   and powering off.

4. The installed system enables sshd (root key login, no password auth), an
   `admin` user with passwordless sudo, and `nix-command` + `flakes`. The host
   forwards port 2222 → guest 22 via `-netdev user,hostfwd=...`.

## Layout

```
test/qemu/
  README.md              this file
  harness.sh             convenience runner (install|boot|test|ssh|stop|...)
  run-vm.sh              QEMU launcher (--mode install|iso|boot, --background, --serial)
  install.sh             orchestrates the unattended install
  serial-console.py      expect-style serial driver (no expect needed)
  provision-project.sh   rsync project into VM + flake smoke test
  assets/
    install-live.sh      install steps executed inside the live ISO
    configuration.nix    installed system config (key placeholder)
  lib/common.sh          shared config + helpers (all settings are env-overridable)
  state/                 runtime state (gitignored)
    nas-vm.qcow2         the VM disk
    provisioning.img     provisioning image (rebuilt each install)
    boot/                extracted kernel/initrd/cmdline (cached per ISO)
    keys/harness-key     SSH key the harness uses to reach the VM
    logs/                console + smoke-test logs
    installed            marker: install completed
```

## Usage

```bash
# 1. Unattended install (long: downloads+builds inside the VM)
test/qemu/harness.sh install
#    watch progress:  tail -f test/qemu/state/logs/install-console.log

# 2. Boot the installed VM (background) and wait for SSH on port 2222
test/qemu/harness.sh boot

# 3. Copy the project into the VM and evaluate the flake
test/qemu/harness.sh test
#    results:  test/qemu/state/logs/smoke-test.log, flake-check.log

# 4. Interact
test/qemu/harness.sh ssh          # root shell in the VM
test/qemu/harness.sh ssh 'nix eval .#nixosConfigurations.nas.config.nas.installationReady'
test/qemu/harness.sh status
test/qemu/harness.sh stop
```

### Tuning (env vars, see `lib/common.sh`)

```bash
QEMU_ISO=/path/to/nixos-minimal-x86_64.iso \
VM_MEM=4096 VM_CPUS=4 VM_DISK_SIZE=40G VM_SSH_PORT=2222 \
test/qemu/harness.sh install
```

## What the smoke test checks and its expected output

`harness.sh test` rsyncs the repo to `/root/nixos-nas` in the VM and runs:

```
nix flake check --no-build
nix eval .#nixosConfigurations.nas.config.nas.installationReady   # → false
```

- `nix eval …installationReady` **must** succeed and print `false`.
- `nix flake check --no-build` is currently **expected to fail** — but only on
  the deliberate pre-install placeholder assertions (no root `fileSystems`,
  no `boot.loader.grub.devices`), i.e. `nas.installationReady = false`.
  The harness logs that failure as *expected*; anything else is flagged.

The first run of the smoke test surfaced (and the fixes were applied to the
project):

| Module | Bug |
|--------|-----|
| `modules/nas/backup.nix` | bare `restic` → `pkgs.restic` |
| `modules/nas/copyparty.nix` | bare `copyparty` → `pkgs.copyparty` |
| `modules/nas/secrets.nix` | missing `caddyCaExportPath` binding (used in vaultwarden health script) |
| `copyparty/zfs/syncthing/tftp/virtualization.nix` | `systemd.services.*.requiresMountsFor` removed in NixOS 26.05 → `unitConfig.RequiresMountsFor` |

## Deliverables / current state

- **(a) Minimal install**: boots a plain NixOS 26.05 with `sshd` + root key
  login on `127.0.0.1:2222`, hostname `nas-vm`, user `admin` (password `admin`)
  with passwordless sudo, flakes enabled.
- **(b) Plumbing for the project flake**: `provision-project.sh` copies the
  repo (minus `test/qemu`, `.git`, `secrets`) to `/root/nixos-nas` and runs
  `nix flake check --no-build` + `nix eval .#nixosConfigurations.nas.config.nas.installationReady`.
  Full `nas` integration is deliberately deferred (the real config needs a
  VM-compatible `hardware-configuration.nix`, systemd-boot/EFI, and
  `installationReady = true`).

## Known limitations & notes

- **BIOS/GRUB, not UEFI/systemd-boot**: chosen for reliability. The project's
  `nas` config uses systemd-boot, so Stage-7 integration will need UEFI. The
  plumbing is in place: set `FIRMWARE=uefi` for `harness.sh boot` (OVMF pflash
  is auto-selected/copied), but a *UEFI unattended install* is not automated
  yet — installing a UEFI guest requires booting the ISO through OVMF (the
  live kernel is booted with `-kernel`/`-initrd`, which the guest sees as a
  BIOS boot, so `efibootmgr` inside `nixos-install` would not see EFI).
- The live ISO uses DHCP via SLIRP (`10.0.2.0/24`, gateway `.2`, DNS `.3`); if
  DNS fails, `install-live.sh` pins `nameserver 10.0.2.3`.
- `nix flake check` inside the VM fetches the pinned inputs from GitHub; the
  first run downloads a few hundred MB. `--no-build` keeps it to evaluation.
- If the unattended install ever becomes flaky, `harness.sh iso` drops you into
  the live ISO shell interactively for a manual install.
- All state lives under `test/qemu/state/`; delete it (or the `installed`
  marker) to reinstall from scratch.
