#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"
CACHE_DIR="${NAS_QEMU_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/nixos-nas-qemu}"
STATE_DIR="${NAS_QEMU_STATE_DIR:-$CACHE_DIR/state}"
NIXOS_CHANNEL="${NAS_NIXOS_CHANNEL:-nixos-26.05}"
ISO_URL="${NAS_NIXOS_ISO_URL:-https://channels.nixos.org/$NIXOS_CHANNEL/latest-nixos-minimal-x86_64-linux.iso}"
ISO_SHA256="${NAS_NIXOS_ISO_SHA256:-}"
SSH_PORT="${NAS_QEMU_SSH_PORT:-2222}"
HTTP_PORT="${NAS_QEMU_HTTP_PORT:-8088}"
HTTPS_PORT="${NAS_QEMU_HTTPS_PORT:-8443}"
COCKPIT_PORT="${NAS_QEMU_COCKPIT_PORT:-9094}"
MEMORY_MIB="${NAS_QEMU_MEMORY_MIB:-10240}"
CPUS="${NAS_QEMU_CPUS:-4}"
OS_DISK_GIB="${NAS_QEMU_OS_DISK_GIB:-32}"
DATA_DISK_GIB="${NAS_QEMU_DATA_DISK_GIB:-8}"
KEEP_VM="${NAS_QEMU_KEEP_VM:-0}"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

usage() {
  cat <<'USAGE'
Usage: scripts/qemu-test.sh [static|native|installer|all|clean]

  static     Run repository tests, Nix evaluation, and build the installable VM closure.
  native     Build and execute both runNixOSTest QEMU integration tests.
  installer  Download/verify the NixOS 26.05 ISO, install the NAS into a fresh
             QEMU disk, reboot it, and execute the in-guest full-stack suite.
  all        Run static, native, and installer paths (default).
  clean      Remove cached VM disks, extracted ISO boot files, and logs.

Environment overrides are documented in docs/development/testing.md. Run through the supplied
shell when host dependencies are missing:
  nix develop .#qemu-test -c ./scripts/qemu-test.sh all
USAGE
}

ensure_host_tools() {
  local cmd
  for cmd in curl sha256sum qemu-system-x86_64 qemu-img expect bsdtar ssh ssh-keygen timeout; do
    need "$cmd"
  done
}

run_static() {
  need nix
  log "Repository preflight and Nix evaluation"
  (cd "$ROOT" && ./scripts/preflight.sh)
  (cd "$ROOT" && nix flake check --no-build --show-trace)
  (cd "$ROOT" && nix build .#nixosConfigurations.nas-ci-ready.config.system.build.toplevel --show-trace -L)
  (cd "$ROOT" && nix build .#nixosConfigurations.nas-qemu.config.system.build.toplevel --show-trace -L)
}

run_native() {
  need nix
  log "NixOS runNixOSTest full-stack QEMU test"
  (cd "$ROOT" && nix build .#checks.x86_64-linux.nas-vm .#checks.x86_64-linux.nas-vm-encrypted --show-trace -L)
}

download_iso() {
  local iso
  iso="$CACHE_DIR/$(basename "${ISO_URL%%\?*}")"
  local checksum_file="$iso.sha256.remote"
  local expected="$ISO_SHA256"
  install -d -m 0755 "$CACHE_DIR"

  if [[ -z "$expected" ]]; then
    if curl --fail --location --retry 3 --retry-all-errors \
      --output "$checksum_file.part" "$ISO_URL.sha256"; then
      mv "$checksum_file.part" "$checksum_file"
      expected="$(grep -Eo '[0-9a-fA-F]{64}' "$checksum_file" | head -n1 || true)"
    else
      rm -f "$checksum_file.part"
    fi
  fi
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || \
    die "could not obtain a SHA-256 checksum for $ISO_URL; set NAS_NIXOS_ISO_SHA256 explicitly"
  expected="${expected,,}"

  if [[ -s "$iso" ]] && ! printf '%s  %s\n' "$expected" "$iso" | sha256sum --check --status; then
    log "Cached installer ISO is stale or corrupt; downloading the current image" >&2
    rm -f "$iso"
  fi
  if [[ ! -s "$iso" ]]; then
    log "Downloading NixOS installer ISO" >&2
    rm -f "$iso.part"
    curl --fail --location --retry 5 --retry-all-errors --output "$iso.part" "$ISO_URL"
    mv "$iso.part" "$iso"
  fi

  printf '%s  %s\n' "$expected" "$iso" | sha256sum --check --status || \
    die "NixOS ISO checksum verification failed: $iso"
  printf '%s\n' "$iso"
}

extract_iso_boot() {
  local iso=$1 out="$CACHE_DIR/iso-boot" entry candidate linux_path initrd_path options
  install -d -m 0755 "$out"
  entry=""
  while IFS= read -r candidate; do
    linux_path="$(bsdtar -xOf "$iso" "$candidate" | awk '$1 == "linux" {sub(/^\//, "", $2); print $2; exit}')"
    initrd_path="$(bsdtar -xOf "$iso" "$candidate" | awk '$1 == "initrd" {sub(/^\//, "", $2); print $2; exit}')"
    options="$(bsdtar -xOf "$iso" "$candidate" | sed -nE 's/^options[[:space:]]+//p' | head -n1)"
    if [[ -n "$linux_path" && -n "$initrd_path" && -n "$options" ]]; then
      entry="$candidate"
      break
    fi
  done < <(bsdtar -tf "$iso" | grep -E '(^|/)loader/entries/.*\.conf$' || true)
  [[ -n "$entry" ]] || die "could not find a usable systemd-boot loader entry in the NixOS ISO"
  bsdtar -xOf "$iso" "$linux_path" > "$out/bzImage"
  bsdtar -xOf "$iso" "$initrd_path" > "$out/initrd"
  [[ -s "$out/bzImage" && -s "$out/initrd" ]] || die "extracted ISO kernel or initrd is empty"
  printf '%s\n' "$options" > "$out/options"
  printf '%s\n' "$out"
}


stage_source_tree() {
  install -d -m 0755 "$STATE_DIR"
  local destination="$STATE_DIR/reviewed-source"
  local temporary="$STATE_DIR/.reviewed-source.$$"
  rm -rf "$temporary"
  mkdir -p "$temporary"
  python3 - "$ROOT" "$temporary" <<'PYSTAGE'
from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
stage = pathlib.Path(sys.argv[2]).resolve()
ignored_parts = {".git", ".cache", ".pytest_cache", "__pycache__", "node_modules", ".direnv", ".venv"}
ignored_names = {".coverage", "coverage.json"}
ignored_suffixes = {".pyc", ".zip", ".qcow2", ".iso", ".log"}


def ignored(path: pathlib.PurePath) -> bool:
    return (
        any(part in ignored_parts or part.endswith(".egg-info") for part in path.parts)
        or path.name in ignored_names
        or path.suffix in ignored_suffixes
        or path.name.endswith((".zip.sha256", ".provenance.json"))
    )

for path in root.rglob("*"):
    relative = path.relative_to(root)
    if ".git" in relative.parts or ignored(relative):
        continue
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise SystemExit(f"QEMU source contains a symlink: {relative}")
    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        raise SystemExit(f"QEMU source contains a non-regular object: {relative}")

if (root / ".git").exists():
    payload = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    selected = [pathlib.PurePosixPath(item.decode()) for item in payload.split(b"\0") if item]
    untracked = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"]
    )
    unexpected = [
        item.decode()
        for item in untracked.split(b"\0")
        if item and not ignored(pathlib.PurePosixPath(item.decode()))
    ]
    if unexpected:
        raise SystemExit("QEMU source has unreviewed files: " + ", ".join(sorted(unexpected)[:20]))
    policy = "git-tracked"
else:
    manifest = root / "MANIFEST.sha256"
    if not manifest.is_file():
        raise SystemExit("QEMU source archive requires MANIFEST.sha256")
    selected = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            raise SystemExit("malformed MANIFEST.sha256")
        name = fields[1].lstrip("*").removeprefix("./")
        selected.append(pathlib.PurePosixPath(name))
    selected.append(pathlib.PurePosixPath("MANIFEST.sha256"))
    policy = "committed-manifest-allowlist"

seen: set[str] = set()
for relative in sorted(selected, key=lambda value: value.as_posix()):
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts) or ignored(relative):
        continue
    name = relative.as_posix()
    if name in seen:
        raise SystemExit(f"duplicate QEMU source path: {name}")
    seen.add(name)
    source = root.joinpath(*relative.parts)
    mode = source.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise SystemExit(f"QEMU source path is not a regular file: {relative}")
    resolved = source.resolve(strict=True)
    if root not in resolved.parents:
        raise SystemExit(f"QEMU source path escapes repository: {relative}")
    target = stage.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target, follow_symlinks=False)
    os.chmod(target, stat.S_IMODE(mode) & 0o777)

(stage / ".nas-source-selection.json").write_text(
    json.dumps({"policy": policy, "files": sorted(seen)}, sort_keys=True) + "\n",
    encoding="utf-8",
)
PYSTAGE
  rm -rf "$destination"
  mv "$temporary" "$destination"
  printf '%s\n' "$destination"
}

source_fingerprint() {
  local source_root=$1
  (
    cd "$source_root"
    while IFS= read -r -d '' path; do
      printf '%s\0' "$path"
      sha256sum "$path"
    done < <(find . -type f -print0 | sort -z)
  ) | sha256sum | awk '{print $1}'
}

qemu_acceleration() {
  if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    printf '%s\n' '-enable-kvm' '-cpu' 'host'
  else
    printf '%s\n' '-machine' 'accel=tcg' '-cpu' 'max'
  fi
}

ssh_options() {
  local key=$1
  printf '%s\n' \
    -i "$key" \
    -o IdentitiesOnly=yes \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null
}

wait_for_ssh() {
  local key=$1 attempts=${NAS_QEMU_SSH_ATTEMPTS:-180}
  local -a options
  mapfile -t options < <(ssh_options "$key")
  for ((i=1; i<=attempts; i++)); do
    if ssh "${options[@]}" -o ConnectTimeout=2 \
      -p "$SSH_PORT" admin@127.0.0.1 true >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

run_installer() {
  ensure_host_tools
  install -d -m 0755 "$STATE_DIR"
  local iso boot_dir os_disk data_disk install_log boot_log pidfile install_marker source_stage source_id marker_id options pid
  local ssh_key ssh_key_dir
  local -a accel ssh_args
  iso="$(download_iso)"
  boot_dir="$(extract_iso_boot "$iso")"
  os_disk="$STATE_DIR/nixos-nas-os.qcow2"
  data_disk="$STATE_DIR/nixos-nas-zfs.qcow2"
  install_log="$STATE_DIR/installer-console.log"
  boot_log="$STATE_DIR/installed-console.log"
  pidfile="$STATE_DIR/qemu.pid"
  install_marker="$STATE_DIR/os-install-complete"
  ssh_key="$STATE_DIR/installer-admin-ed25519"
  ssh_key_dir="$STATE_DIR/ssh-key"
  source_stage="$(stage_source_tree)"
  source_id="$(source_fingerprint "$source_stage")"
  marker_id="$(cat "$install_marker" 2>/dev/null || true)"

  rm -f "$pidfile" "$install_log" "$boot_log"
  if [[ "$KEEP_VM" != 1 || ! -s "$os_disk" || ! -s "$ssh_key" || "$marker_id" != "$source_id" ]]; then
    rm -f "$os_disk" "$data_disk" "$install_marker" "$ssh_key" "$ssh_key.pub"
    rm -rf "$ssh_key_dir"
    install -d -m 0700 "$ssh_key_dir"
    ssh-keygen -q -t ed25519 -N '' -C 'nixos-nas-qemu-ephemeral' -f "$ssh_key"
    install -m 0644 "$ssh_key.pub" "$ssh_key_dir/admin.pub"
    qemu-img create -q -f qcow2 "$os_disk" "${OS_DISK_GIB}G"
    qemu-img create -q -f qcow2 "$data_disk" "${DATA_DISK_GIB}G"

    mapfile -t accel < <(qemu_acceleration)
    options="$(cat "$boot_dir/options") console=ttyS0,115200n8 systemd.show_status=1"
    log "Installing NixOS NAS into a fresh QEMU disk"
    "$ROOT/tests/vm/install.expect" \
      qemu-system-x86_64 \
      "${accel[@]}" \
      -m "$MEMORY_MIB" -smp "$CPUS" \
      -kernel "$boot_dir/bzImage" -initrd "$boot_dir/initrd" -append "$options" \
      -drive "file=$iso,media=cdrom,readonly=on" \
      -drive "file=$os_disk,format=qcow2,if=virtio" \
      -drive "file=$data_disk,format=qcow2,if=virtio" \
      -virtfs "local,path=$source_stage,mount_tag=nas-source,security_model=none,readonly=on" \
      -virtfs "local,path=$ssh_key_dir,mount_tag=nas-ssh-key,security_model=none,readonly=on" \
      -device virtio-rng-pci \
      -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
      -no-reboot -nographic 2>&1 | tee "$install_log"
    printf '%s\n' "$source_id" > "$install_marker"
  else
    log "Reusing the installed OS disk because NAS_QEMU_KEEP_VM=1 and the source tree is unchanged"
  fi

  rm -f "$data_disk"
  qemu-img create -q -f qcow2 "$data_disk" "${DATA_DISK_GIB}G"

  mapfile -t accel < <(qemu_acceleration)
  log "Booting installed NAS and running the full suite inside the VM"
  qemu-system-x86_64 \
    "${accel[@]}" \
    -m "$MEMORY_MIB" -smp "$CPUS" \
    -drive "file=$os_disk,format=qcow2,if=virtio" \
    -drive "file=$data_disk,format=qcow2,if=virtio" \
    -device virtio-rng-pci \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$HTTP_PORT-:80,hostfwd=tcp:127.0.0.1:$HTTPS_PORT-:443,hostfwd=tcp:127.0.0.1:$COCKPIT_PORT-:9092" \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial "file:$boot_log" -daemonize -pidfile "$pidfile"

  cleanup_vm() {
    if [[ -s "$pidfile" ]]; then
      local pid
      pid="$(cat "$pidfile")"
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
      kill -KILL "$pid" 2>/dev/null || true
      rm -f "$pidfile"
    fi
  }
  trap cleanup_vm EXIT INT TERM

  mapfile -t ssh_args < <(ssh_options "$ssh_key")
  if ! wait_for_ssh "$ssh_key"; then
    cat "$boot_log" >&2 || true
    die "installed VM did not become reachable over SSH on port $SSH_PORT"
  fi

  timeout --foreground "${NAS_QEMU_GUEST_TEST_TIMEOUT:-3600}" \
    ssh "${ssh_args[@]}" \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=20 \
      -p "$SSH_PORT" admin@127.0.0.1 \
      "sudo -n env NAS_TEST_TIMEOUT=600 nas-vm-guest-test /dev/vdb"

  log "Exercising post-install activation, failed-candidate, and rollback paths"
  timeout --foreground "${NAS_QEMU_RECONFIGURE_TIMEOUT:-5400}" \
    ssh "${ssh_args[@]}" \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=20 \
      -p "$SSH_PORT" admin@127.0.0.1 \
      'sudo -n env NAS_TEST_REBUILD_TIMEOUT=1800 nas-vm-reconfigure-test'

  ssh "${ssh_args[@]}" \
    -p "$SSH_PORT" admin@127.0.0.1 'sudo -n poweroff' >/dev/null 2>&1 || true
  if [[ -s "$pidfile" ]]; then
    pid="$(cat "$pidfile")"
    for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  fi
  cleanup_vm

  boot_log="$STATE_DIR/post-switch-console.log"
  rm -f "$boot_log" "$pidfile"
  log "Rebooting the switched generation for persistence verification"
  qemu-system-x86_64 \
    "${accel[@]}" \
    -m "$MEMORY_MIB" -smp "$CPUS" \
    -drive "file=$os_disk,format=qcow2,if=virtio" \
    -drive "file=$data_disk,format=qcow2,if=virtio" \
    -device virtio-rng-pci \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$HTTP_PORT-:80,hostfwd=tcp:127.0.0.1:$HTTPS_PORT-:443,hostfwd=tcp:127.0.0.1:$COCKPIT_PORT-:9092" \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial "file:$boot_log" -daemonize -pidfile "$pidfile"
  trap cleanup_vm EXIT INT TERM
  if ! wait_for_ssh "$ssh_key"; then
    cat "$boot_log" >&2 || true
    die "post-switch VM did not become reachable over SSH on port $SSH_PORT"
  fi
  ssh "${ssh_args[@]}" -p "$SSH_PORT" admin@127.0.0.1 \
    'set -euo pipefail; \
     test "$(cat /var/lib/nas-install-test/reinstall-sentinel)" = preserve-me; \
     sudo -n nas-doctor --json >/tmp/nas-post-switch-reboot-doctor.json'
  ssh "${ssh_args[@]}" \
    -p "$SSH_PORT" admin@127.0.0.1 'sudo -n poweroff' >/dev/null 2>&1 || true
  if [[ -s "$pidfile" ]]; then
    pid="$(cat "$pidfile")"
    for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  fi
  trap - EXIT INT TERM
  cleanup_vm
  log "Installed-VM test completed successfully"
}

case "$MODE" in
  static) run_static ;;
  native) run_native ;;
  installer) run_installer ;;
  all) run_static; run_native; run_installer ;;
  clean) rm -rf "$CACHE_DIR"; log "Removed $CACHE_DIR" ;;
  -h|--help|help) usage ;;
  *) usage >&2; die "unknown mode: $MODE" ;;
esac
