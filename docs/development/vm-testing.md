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

## Full suite on a non-NixOS host

Use the persistent QEMU wrapper when the host is not NixOS or should not run
the appliance tests directly. The first start downloads and verifies the
standard NixOS minimal ISO, installs the existing `nas-qemu` configuration into
a disposable qcow2 disk, saves a clean QEMU baseline snapshot, and boots it.
Later test runs restore that baseline, refresh the current worktree inside the
guest, rebuild the installed generation, and run the suite. This keeps repeated
runs independent without reinstalling NixOS or downloading the ISO again.

```bash
./scripts/vm-start.sh   # install once if needed, then boot the VM
./scripts/vm-pytest.sh  # copy the current worktree and run the full suite in it
./scripts/vm-stop.sh    # stop the VM and keep the installed disk
./scripts/vm-reset.sh   # remove the installed disk and logs; ISO is retained
```

`vm-pytest.sh` runs source preflight, unit/security/property/JavaScript tests,
Nix configuration and negative fixtures, then the existing full-stack,
browser, storage, secret, and installed-command checks. The source is copied
from the worktree on every run, including new untracked files while excluding
Git metadata and generated/runtime artifacts. Nix and all tests execute in the
guest; the wrapper first runs `nixos-rebuild switch` from that copied source so
the installed generation and its test commands follow the current worktree.
The host only stages files and drives SSH.

The guest uses QEMU user-mode networking (`-netdev user`) solely for the ISO,
Nix input, and package downloads. No host bridge, tap device, NIC passthrough,
or physical host interface is required. VM state is kept under the user cache,
not in the repository. These wrappers are additive developer tools and do not
change CI check ownership; the CI VM jobs invoke the same lifecycle and now
declare their host-side dependencies explicitly.

The installed VM forwards SSH, Caddy HTTP/HTTPS, and Cockpit to the host. The
default bind address is loopback, so after `vm-start.sh` you can inspect the
appliance at `http://127.0.0.1:8088`, `https://127.0.0.1:8443`, and
`https://127.0.0.1:9094` without a bridge or host NIC. Use
`NAS_QEMU_HOST_BIND_ADDRESS=0.0.0.0` only when another machine must reach the
test VM; user-mode networking remains in use and the forwarded services are
then exposed on every host interface.

The persistent wrapper defaults to a 64 GiB OS disk so the complete Nix store,
test dependencies, and repeated rebuild generations fit comfortably. Override
`NAS_QEMU_OS_DISK_GIB` only when a smaller or larger disposable disk is
intentional; changing the size of an existing VM requires `scripts/vm-reset.sh`.

`vm-pytest.sh` restores the cached `nas-test-clean` QEMU snapshot before each
test run. A cache created by an older wrapper without that snapshot must be
reset once.

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
4. creates a fresh 64 GiB qcow2 OS disk and an 8 GiB ZFS data disk;
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
| `persistent-start` | Install once if needed, boot the reusable QEMU VM, and leave it running. |
| `persistent-test` | Restore the clean persistent baseline, copy the current worktree, rebuild, and run the complete guest suite. |
| `persistent-stop` | Stop the reusable VM while keeping its disks and baseline snapshot. |
| `persistent-reset` | Remove the reusable VM state while keeping the cached ISO. |
| `all` | Runs `static`, `native`, then `installer`. |
| `clean` | Deletes the QEMU test cache, disks, extracted boot files, and logs. |

## What the guest suite validates

The full-stack paths share `tests/vm/guest-test.sh`. The native matrix also
runs `tests/vm/encrypted-guest-test.sh`. Together they validate:

The guest watchdog is derived from [`tests/vm/timeout-budget.json`](../../tests/vm/timeout-budget.json),
which is consumed by the native NixOS test, the installed-QEMU wrapper, and the
guest phase profiler. Add a phase or bounded wait there instead of changing one
wrapper timeout independently.

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
| `NAS_QEMU_MEMORY_MIB` | `8192` | Installed VM memory. |
| `NAS_QEMU_CPUS` | `2` | Installed VM virtual CPUs. |
| `NAS_QEMU_OS_DISK_GIB` | `64` | Disposable OS disk size. |
| `NAS_QEMU_DATA_DISK_GIB` | `8` | Disposable ZFS disk size. |
| `NAS_QEMU_SSH_PORT` | `2222` | Loopback SSH forwarding port. |
| `NAS_QEMU_HTTP_PORT` | `8088` | Host port forwarded to guest HTTP port 80. |
| `NAS_QEMU_HTTPS_PORT` | `8443` | Host port forwarded to guest HTTPS port 443. |
| `NAS_QEMU_COCKPIT_PORT` | `9094` | Host port forwarded to guest Cockpit port 9092. |
| `NAS_QEMU_HOST_BIND_ADDRESS` | `127.0.0.1` | Host IPv4 address used for SSH, HTTP, HTTPS, and Cockpit forwarding. |
| `NAS_QEMU_KEEP_VM` | `0` | Legacy disposable-mode reuse switch; the persistent wrappers manage reuse and baseline restore explicitly. |
| `NAS_QEMU_PERSISTENT_REBUILD_TIMEOUT` | manifest `reconfigureBuild` | Guest `nixos-rebuild switch` deadline for the persistent wrapper. |
| `NAS_QEMU_SOURCE_SUITE_TIMEOUT` | manifest-derived | Host-side deadline for the full source/appliance suite in the persistent VM. |
| `NAS_QEMU_GUEST_TEST_TIMEOUT` | manifest-derived | Host-side limit for the installed guest suite; it is the sum of every declared guest phase plus slack. |

The qualified build exports `bundle-manifest.tsv` beside the NAR archives. It
records the store paths owned by the core and application archives plus the
configuration-sensitive `vm-drivers` delta, rejecting overlap between bundle
deltas when a path is claimed by `vm-drivers`. Application closures may share
ordinary transitive dependencies. The core archive contains boot/unlock and common test tooling; the
identity, observability, storage, and AI application archives remain separate.
The cache persistence job is intentionally non-authoritative: a cache upload
warning is printed in the CI summary, while the exact bundle handoff remains
the source of truth for the QEMU jobs.

The installer harness creates an ephemeral Ed25519 key under the private VM
state directory, injects only its public key, disables password and
keyboard-interactive SSH authentication, and removes the key with `clean`.
The cache and state overrides must name dedicated directories. The wrapper
creates a marker in a new cache directory and refuses to remove an existing
directory that it did not create; `NAS_QEMU_STATE_DIR` must remain below
`NAS_QEMU_CACHE_DIR`. This prevents `clean` and `persistent-reset` from
mistaking a general-purpose directory for VM state.

## Failure evidence

Native test logs are printed by the NixOS test driver. The installer path keeps:

- `installer-console.log` — official ISO boot and `nixos-install` output;
- `installed-console.log` — installed-system serial console;
- the persistent OS and ZFS qcow2 disks plus the `nas-test-clean` baseline snapshot when using the persistent wrapper.

The guest error trap prints failed units, the last 250 journal lines, and ZFS
status before returning a failure. To remove all retained state:

```bash
./scripts/qemu-test.sh clean
```
