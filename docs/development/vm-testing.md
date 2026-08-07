# QEMU and installer validation

This release contains two disposable QEMU test paths. Both execute the live NAS
validation suite inside NixOS guests. They do not touch host disks, pools, users,
or services.

## Fast path: NixOS integration driver

The native NixOS test matrix builds two VMs directly from the flake. The first
attaches a blank 8 GiB virtio disk and runs the complete application,
authentication, and service suite on an unencrypted disposable dataset. The
second enables native ZFS encryption and exercises encrypted-dataset creation,
recovery-key export, lock/unload, and KeePass-driven unlock/remount.

```bash
nix build .#checks.x86_64-linux.nas-vm \
  .#checks.x86_64-linux.nas-vm-encrypted -L
```

The equivalent wrapper is:

```bash
./scripts/qemu-test.sh native
```

This is the normal development and CI path. Nix provides the QEMU test driver,
serial capture, deterministic machine definition, and failure logs.

## Full installer path

The installer test proves the setup from an official NixOS installer rather
than booting a test-driver machine directly. It:

1. downloads the current minimal x86_64 ISO from the configured NixOS 26.05
   channel;
2. downloads and verifies the ISO SHA-256 checksum;
3. extracts the ISO kernel, initrd, and boot arguments for a reliable serial
   console;
4. creates fresh qcow2 OS and ZFS disks;
5. boots the official installer in QEMU;
6. partitions and formats the OS disk;
7. runs `nixos-install --flake path:/mnt-source#nas-qemu` from inside the
   installer;
8. repeats `nixos-install` onto the already-mounted root and verifies unrelated persistent state survives;
9. shuts down, boots the installed system, waits for SSH, and runs `nas-vm-guest-test` inside that VM;
10. runs an in-place `nixos-rebuild test` from the staged source and checks `nas-doctor` again;
11. powers the VM off after a successful run.

Run it with:

```bash
./scripts/qemu-test.sh installer
```

Run every host/static, native-VM, and full-installer check with:

```bash
./scripts/qemu-test.sh all
```

When QEMU, Expect, libarchive, or OpenSSH are not installed globally, use the
provided development shell:

```bash
nix develop .#qemu-test -c ./scripts/qemu-test.sh all
```

## Modes

| Mode | Purpose |
|---|---|
| `static` | Repository preflight, flake evaluation, and builds of the CI-ready and installable QEMU systems. |
| `native` | Both `runNixOSTest` VMs: complete stack plus encrypted-ZFS lifecycle. |
| `installer` | Official ISO download, fresh install, repeated declarative install, reboot, complete in-guest suite, and in-place reconfiguration. |
| `all` | Runs `static`, `native`, then `installer`. |
| `clean` | Deletes the QEMU test cache, disks, extracted boot files, and logs. |

## What the guest suite validates

The full-stack paths share `tests/vm/guest-test.sh`. The native matrix also
runs `tests/vm/encrypted-guest-test.sh`. Together they validate:

- locked boot: Cockpit remains reachable while Authentik, Caddy, CopyParty, and
  other protected services remain stopped;
- a disposable `tank/nas` ZFS dataset mounted at `/tank`, including mount-source
  and filesystem-type checks;
- disabled encryption and UPS command guards, including encryption/UPS guard behavior;
- KeePassXC database creation, machine-secret initialization, incorrect-password
  rejection, atomic activation, stop, reactivation, and active-state rollback;
- Authentik startup, API token behavior, reserved administrator policy, and
  generated capability model;
- default-deny, explicit-allow, and administrator decisions at the Unix-socket
  authorization gate;
- trusted CopyParty identity headers at the backend, plus proof that identical
  client-supplied headers cannot bypass Caddy/Authentik;
- unauthenticated blocking or login redirection for files, administrator shares,
  Cockpit, Open WebUI, Syncthing, Vaultwarden administration, metrics, and alerts;
- CopyParty Unix-socket reachability, anonymous TFTP reads, default read-only TFTP write rejection, and Authentik health;
- all custom `nas-*` command surfaces, including in-VM repository preflight, Python tests, Node tests, JSON/TOML checks, and flake evaluation;
- adversarial command-shaped identifiers, SQL-like account names, traversal-shaped setup paths, and malformed alert HTTP bodies fail closed without side effects or tracebacks;
- a repeated declarative installation preserves unrelated persistent state and the booted system survives an in-place rebuild/test;
- llama-swap and Open WebUI in Always, Off, and On-demand/wake modes;
- VictoriaMetrics, Telegraf, vmalert, the NAS alert router, Grafana, ntfy, Syncthing, Vaultwarden,
  alert delivery, and Cockpit ZFS/documentation assets;
- no unexpected failed units and a healthy final ZFS pool;
- native-ZFS encryption-root creation from a KeePassXC-generated key;
- root-only recovery-key export and byte-for-byte verification;
- full `nas-zfs-lock` unmount/key-unload followed by secret reactivation,
  fingerprint validation, and remount.

All keys and pools used by these tests are disposable VM data. Importing a
pre-existing encrypted pool from independent recovery media remains a separate
hardware/recovery drill.

## Host requirements

The wrapper requires Linux. `static`, `native`, and `all` require `nix` with
flakes enabled. The standalone `installer` mode does not invoke host Nix, but it
requires:

- `qemu-system-x86_64` and `qemu-img`;
- `expect`;
- `bsdtar` from libarchive;
- `curl`, `sha256sum`, OpenSSH, and `timeout`.

KVM is used automatically when `/dev/kvm` is readable and writable. Otherwise
the installer path falls back to QEMU TCG, which is substantially slower. The
native NixOS test uses the acceleration available to Nix/QEMU on the host.

The full installer guest needs outbound network access to obtain flake inputs
and Nix store paths. QEMU user networking provides this by default.

## Environment overrides

| Variable | Default | Meaning |
|---|---:|---|
| `NAS_QEMU_CACHE_DIR` | `$XDG_CACHE_HOME/nixos-nas-qemu` | ISO, extracted boot files, disks, and logs. |
| `NAS_QEMU_STATE_DIR` | `$NAS_QEMU_CACHE_DIR/state` | VM disks and console logs. |
| `NAS_NIXOS_CHANNEL` | `nixos-26.05` | Installer channel. |
| `NAS_NIXOS_ISO_URL` | channel minimal ISO | Alternate official/local ISO URL. |
| `NAS_NIXOS_ISO_SHA256` | downloaded sidecar | Explicit trusted ISO checksum. |
| `NAS_QEMU_MEMORY_MIB` | `10240` | Installed VM memory. |
| `NAS_QEMU_CPUS` | `4` | Installed VM virtual CPUs. |
| `NAS_QEMU_OS_DISK_GIB` | `32` | Disposable OS disk size. |
| `NAS_QEMU_DATA_DISK_GIB` | `8` | Disposable ZFS disk size. |
| `NAS_QEMU_SSH_PORT` | `2222` | Loopback SSH forwarding port. |
| `NAS_QEMU_KEEP_VM` | `0` | Set to `1` to reuse the installed OS disk only when the source tree is unchanged; the ZFS data disk is always recreated. |
| `NAS_QEMU_GUEST_TEST_TIMEOUT` | `3600` | Host-side limit for the installed guest suite. |

The installer harness creates an ephemeral Ed25519 key under the private VM
state directory, injects only its public key, disables password and
keyboard-interactive SSH authentication, and removes the key with `clean`.

## Failure evidence

Native test logs are printed by the NixOS test driver. The installer path keeps:

- `installer-console.log` — official ISO boot and `nixos-install` output;
- `installed-console.log` — installed-system serial console;
- the source-matched installed OS qcow2 disk when `NAS_QEMU_KEEP_VM=1`; the ZFS data disk is recreated for every test run.

The guest error trap prints failed units, the last 250 journal lines, and ZFS
status before returning a failure. To remove all retained state:

```bash
./scripts/qemu-test.sh clean
```
