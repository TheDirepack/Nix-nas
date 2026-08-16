#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/tests/vm/timeout-budget.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/nas-qemu-process.sh"
export NAS_VM_TIMEOUT_BUDGET_FILE="${NAS_VM_TIMEOUT_BUDGET_FILE:-$ROOT/tests/vm/timeout-budget.json}"
MODE="${1:-all}"
DEFAULT_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/nixos-nas-qemu"
CACHE_DIR="${NAS_QEMU_CACHE_DIR:-$DEFAULT_CACHE_DIR}"
STATE_DIR="${NAS_QEMU_STATE_DIR:-$CACHE_DIR/state}"
CACHE_MARKER="$CACHE_DIR/.nas-qemu-cache"
CACHE_MARKER_CONTENT="nixos-nas-qemu-cache-v1"
NIXOS_CHANNEL="${NAS_NIXOS_CHANNEL:-nixos-26.05}"
ISO_URL="${NAS_NIXOS_ISO_URL:-https://channels.nixos.org/$NIXOS_CHANNEL/latest-nixos-minimal-x86_64-linux.iso}"
ISO_SHA256="${NAS_NIXOS_ISO_SHA256:-}"
SSH_PORT="${NAS_QEMU_SSH_PORT:-2222}"
HTTP_PORT="${NAS_QEMU_HTTP_PORT:-8088}"
HTTPS_PORT="${NAS_QEMU_HTTPS_PORT:-8443}"
COCKPIT_PORT="${NAS_QEMU_COCKPIT_PORT:-9094}"
HOST_BIND_ADDRESS="${NAS_QEMU_HOST_BIND_ADDRESS:-127.0.0.1}"
MEMORY_MIB="${NAS_QEMU_MEMORY_MIB:-8192}"
CPUS="${NAS_QEMU_CPUS:-2}"
OS_DISK_GIB="${NAS_QEMU_OS_DISK_GIB:-64}"
DATA_DISK_GIB="${NAS_QEMU_DATA_DISK_GIB:-8}"
BASELINE_SNAPSHOT="nas-test-clean"
KEEP_VM="${NAS_QEMU_KEEP_VM:-0}"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

validate_host_bind_address() {
  local first second third fourth extra octet
  IFS=. read -r first second third fourth extra <<<"$HOST_BIND_ADDRESS"
  [[ -n "$first" && -n "$second" && -n "$third" && -n "$fourth" && -z "$extra" ]] ||
    die "NAS_QEMU_HOST_BIND_ADDRESS must be an IPv4 address: $HOST_BIND_ADDRESS"
  for octet in "$first" "$second" "$third" "$fourth"; do
    if ! [[ "$octet" =~ ^[0-9]{1,3}$ ]] || ! ((10#$octet <= 255)); then
      die "NAS_QEMU_HOST_BIND_ADDRESS must be an IPv4 address: $HOST_BIND_ADDRESS"
    fi
  done
}

qemu_network_args() {
  validate_host_bind_address
  printf '%s\n' \
    -netdev \
    "user,id=net0,hostfwd=tcp:$HOST_BIND_ADDRESS:$SSH_PORT-:22,hostfwd=tcp:$HOST_BIND_ADDRESS:$HTTPS_PORT-:443,hostfwd=tcp:$HOST_BIND_ADDRESS:$COCKPIT_PORT-:9092" \
    -device \
    virtio-net-pci,netdev=net0
}

validate_host_bind_address

usage() {
  cat <<'USAGE'
Usage: scripts/qemu-test.sh [static|native|installer|persistent-start|persistent-test|persistent-stop|persistent-reset|all|clean]

  static     Run repository tests, Nix evaluation, and build the installable VM closure.
  native     Build and execute both runNixOSTest QEMU integration tests.
  installer  Download/verify the NixOS 26.05 ISO, install the NAS into a fresh
             QEMU disk, reboot it, and execute the in-guest full-stack suite.
  persistent-start
             Install the NAS into a reusable QEMU disk on first use and leave
             the VM running for the developer wrapper.
  persistent-test
             Refresh the current worktree inside the reusable VM and run the
             complete source and appliance suite there.
  persistent-stop
             Stop the reusable QEMU VM without deleting its installed disk.
  persistent-reset
             Stop the reusable VM and delete its installed disk and logs.
  all        Run static, native, and installer paths (default).
  clean      Remove cached VM disks, extracted ISO boot files, and logs.

Environment overrides are documented in docs/development/testing.md. Run through the supplied
shell when host dependencies are missing:
  nix develop .#qemu-test -c ./scripts/qemu-test.sh all
USAGE
}

ensure_host_tools() {
  local cmd
  for cmd in curl sha256sum realpath readlink qemu-system-x86_64 qemu-img expect bsdtar ssh ssh-keygen timeout python3 tar jq; do
    need "$cmd"
  done
}

validate_cache_path() {
  local resolved
  [[ -n "$CACHE_DIR" ]] || die "NAS_QEMU_CACHE_DIR must not be empty"
  resolved="$(realpath -m -- "$CACHE_DIR")" || die "cannot resolve NAS_QEMU_CACHE_DIR: $CACHE_DIR"
  case "$resolved" in
    /|"$ROOT"|"$ROOT"/*|"$HOME")
      die "refusing to use an unsafe QEMU cache path: $CACHE_DIR"
      ;;
  esac
  [[ ! -L "$CACHE_DIR" ]] || die "NAS_QEMU_CACHE_DIR must not be a symlink: $CACHE_DIR"
}

ensure_cache_dir() {
  local existed=0
  validate_cache_path
  [[ -e "$CACHE_DIR" ]] && existed=1
  [[ ! -e "$CACHE_DIR" || -d "$CACHE_DIR" ]] || die "QEMU cache path is not a directory: $CACHE_DIR"
  install -d -m 0755 "$CACHE_DIR"
  if [[ -e "$CACHE_MARKER" ]]; then
    [[ ! -L "$CACHE_MARKER" && -f "$CACHE_MARKER" ]] || die "QEMU cache marker is not a regular file: $CACHE_MARKER"
    [[ "$(<"$CACHE_MARKER")" == "$CACHE_MARKER_CONTENT" ]] || die "QEMU cache marker is invalid: $CACHE_MARKER"
  elif (( existed == 1 )) && [[ "$CACHE_DIR" != "$DEFAULT_CACHE_DIR" ]]; then
    die "refusing to use an existing unrecognized QEMU cache directory: $CACHE_DIR"
  else
    printf '%s\n' "$CACHE_MARKER_CONTENT" > "$CACHE_MARKER"
    chmod 0644 "$CACHE_MARKER"
  fi
}

require_cache_marker() {
  validate_cache_path
  [[ -d "$CACHE_DIR" ]] || return 0
  [[ -e "$CACHE_MARKER" && ! -L "$CACHE_MARKER" && -f "$CACHE_MARKER" ]] || \
    die "refusing to remove an unrecognized QEMU cache directory: $CACHE_DIR"
  [[ "$(<"$CACHE_MARKER")" == "$CACHE_MARKER_CONTENT" ]] || \
    die "refusing to remove a QEMU cache directory with an invalid marker: $CACHE_DIR"
}

validate_state_path() {
  local cache_resolved state_resolved
  validate_cache_path
  cache_resolved="$(realpath -m -- "$CACHE_DIR")" || die "cannot resolve QEMU cache path: $CACHE_DIR"
  state_resolved="$(realpath -m -- "$STATE_DIR")" || die "cannot resolve QEMU state path: $STATE_DIR"
  case "$state_resolved" in
    "$cache_resolved"/*) ;;
    *) die "QEMU state path must be below the cache path: $STATE_DIR" ;;
  esac
  [[ "$state_resolved" != "$cache_resolved" ]] || die "QEMU state path must not equal the cache path"
  [[ ! -L "$STATE_DIR" ]] || die "NAS_QEMU_STATE_DIR must not be a symlink: $STATE_DIR"
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
  ensure_cache_dir

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
  local iso=$1 out="$CACHE_DIR/iso-boot" entry candidate linux_path initrd_path options isolinux_config
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
  if [[ -z "$entry" ]] && isolinux_config="$(bsdtar -xOf "$iso" isolinux/isolinux.cfg 2>/dev/null)"; then
    linux_path="$(printf '%s\n' "$isolinux_config" | awk '$1 == "LINUX" {print $2; exit}')"
    initrd_path="$(printf '%s\n' "$isolinux_config" | awk '$1 == "INITRD" {print $2; exit}')"
    options="$(printf '%s\n' "$isolinux_config" | awk '$1 == "APPEND" {$1=""; sub(/^[[:space:]]+/, ""); print; exit}')"
    linux_path="${linux_path#/}"
    linux_path="${linux_path//\/\//\/}"
    initrd_path="${initrd_path#/}"
    initrd_path="${initrd_path//\/\//\/}"
    if [[ -n "$linux_path" && -n "$initrd_path" && -n "$options" ]]; then
      entry="isolinux/isolinux.cfg"
    fi
  fi
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
  if ! python3 - "${1:-${NAS_QEMU_SOURCE_ROOT:-$ROOT}}" "$temporary" <<'PYSTAGE'
from __future__ import annotations

import json
import hashlib
import os
import pathlib
import shutil
import stat
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
stage = pathlib.Path(sys.argv[2]).resolve()
ignored_parts = {
    ".git",
    ".cache",
    ".hypothesis",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    ".direnv",
    ".venv",
}
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
    selected.extend(
        pathlib.PurePosixPath(item.decode())
        for item in untracked.split(b"\0")
        if item and not ignored(pathlib.PurePosixPath(item.decode()))
    )
    policy = "git-tracked-and-worktree"
else:
    manifest = root / "MANIFEST.sha256"
    if not manifest.is_file():
        raise SystemExit("QEMU source archive requires MANIFEST.sha256")
    selected = []
    manifest_hashes = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            raise SystemExit("malformed MANIFEST.sha256")
        digest, raw_name = fields
        if len(digest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in digest):
            raise SystemExit(f"malformed MANIFEST.sha256 digest: {digest}")
        name = raw_name.lstrip("*").removeprefix("./")
        if name == "MANIFEST.sha256":
            continue
        if name in manifest_hashes:
            raise SystemExit(f"duplicate MANIFEST.sha256 path: {name}")
        manifest_hashes[name] = digest.lower()
        selected.append(pathlib.PurePosixPath(name))
    selected.append(pathlib.PurePosixPath("MANIFEST.sha256"))
    policy = "committed-manifest-allowlist"

seen: set[str] = set()
for relative in sorted(selected, key=lambda value: value.as_posix()):
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SystemExit(f"invalid QEMU source path: {relative}")
    if policy == "git-tracked-and-worktree" and ignored(relative):
        continue
    name = relative.as_posix()
    if name in seen:
        raise SystemExit(f"duplicate QEMU source path: {name}")
    seen.add(name)
    source = root.joinpath(*relative.parts)
    try:
        mode = source.lstat().st_mode
    except FileNotFoundError as error:
        raise SystemExit(f"QEMU source path is missing: {relative}") from error
    if not stat.S_ISREG(mode):
        raise SystemExit(f"QEMU source path is not a regular file: {relative}")
    resolved = source.resolve(strict=True)
    if root not in resolved.parents:
        raise SystemExit(f"QEMU source path escapes repository: {relative}")
    if policy == "committed-manifest-allowlist":
        expected_digest = manifest_hashes.get(name)
        if expected_digest is not None:
            actual_digest = hashlib.sha256(source.read_bytes()).hexdigest()
            if actual_digest != expected_digest:
                raise SystemExit(f"QEMU source manifest digest mismatch: {relative}")
    target = stage.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target, follow_symlinks=False)
    os.chmod(target, stat.S_IMODE(mode) & 0o777)

(stage / ".nas-source-selection.json").write_text(
    json.dumps({"policy": policy, "files": sorted(seen)}, sort_keys=True) + "\n",
    encoding="utf-8",
)
PYSTAGE
  then
    rm -rf -- "$temporary"
    return 1
  fi
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

sync_source_to_guest() {
  local source_stage=$1 ssh_key=$2
  local -a ssh_args
  mapfile -t ssh_args < <(ssh_options "$ssh_key")
  log "Refreshing the current worktree inside the running VM"
  set +e
  tar --exclude=./.nas-source-selection.json -C "$source_stage" -cf - . | \
    ssh "${ssh_args[@]}" \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=20 \
      -p "$SSH_PORT" admin@127.0.0.1 \
      'sudo -n rm -rf /var/lib/nas-test/repo &&
       sudo -n install -d -m 0755 /var/lib/nas-test/repo &&
       sudo -n tar -C /var/lib/nas-test/repo -xf - &&
       sudo -n git -C /var/lib/nas-test/repo init -q &&
       sudo -n git -C /var/lib/nas-test/repo config user.name "NixOS NAS VM" &&
       sudo -n git -C /var/lib/nas-test/repo config user.email "vm-test@nas.local" &&
       sudo -n git -C /var/lib/nas-test/repo add -A &&
       sudo -n git -C /var/lib/nas-test/repo commit -q -m "VM test source"'
  local -a pipeline_status=("${PIPESTATUS[@]}")
  set -e
  if (( pipeline_status[0] != 0 || pipeline_status[1] != 0 )); then
    die "failed to copy the current worktree into the VM (tar=${pipeline_status[0]}, ssh=${pipeline_status[1]})"
  fi
}

rebuild_guest_source() {
  local ssh_key=$1 timeout_seconds="${NAS_QEMU_PERSISTENT_REBUILD_TIMEOUT:-$(nas_vm_timeout_value reconfigureBuild)}"
  local -a ssh_args
  mapfile -t ssh_args < <(ssh_options "$ssh_key")
  log "Updating the installed NixOS generation from the refreshed worktree"
  timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" "$timeout_seconds" \
    ssh "${ssh_args[@]}" \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=20 \
      -p "$SSH_PORT" admin@127.0.0.1 \
      'sudo -n systemctl reset-failed &&
       sudo -n nixos-rebuild switch --flake path:/var/lib/nas-test/repo#nas-qemu --option max-jobs 1 --option cores 2 --option warn-dirty false'
}

stop_persistent_vm() {
  local pidfile="$STATE_DIR/qemu.pid" pid
  if [[ ! -s "$pidfile" ]]; then
    log "Persistent VM is not running."
    return 0
  fi
  if nas_qemu_pid_from_pidfile "$pidfile"; then
    pid="$QEMU_PID"
  else
    local status=$?
    (( status == 2 )) && die "refusing to stop the process recorded in $pidfile"
    rm -f "$pidfile"
    log "Persistent VM is not running."
    return 0
  fi
  log "Stopping persistent VM (pid $pid)"
  nas_qemu_stop_pidfile "$pidfile" 30 || {
    local status=$?
    (( status == 2 )) && die "refusing to stop a pidfile owned by a non-QEMU process"
    return "$status"
  }
}

has_snapshot() {
  local disk=$1
  qemu-img snapshot -l "$disk" | awk -v tag="$BASELINE_SNAPSHOT" '
    NR > 2 && $2 == tag { found = 1 }
    END { exit found ? 0 : 1 }
  '
}

restore_persistent_baseline() {
  local os_disk=$1 data_disk=$2
  stop_persistent_vm
  if ! has_snapshot "$os_disk" || ! has_snapshot "$data_disk"; then
    die "persistent VM baseline is missing; run scripts/vm-reset.sh once to recreate it"
  fi
  log "Restoring the clean persistent VM baseline"
  qemu-img snapshot -a "$BASELINE_SNAPSHOT" "$os_disk"
  qemu-img snapshot -a "$BASELINE_SNAPSHOT" "$data_disk"
}

reset_persistent_state() {
  [[ -d "$CACHE_DIR" ]] || { log "Persistent VM state is not present."; return 0; }
  validate_state_path
  require_cache_marker
  stop_persistent_vm
  rm -rf -- "$STATE_DIR"
  log "Persistent VM state removed; the cached installer ISO was kept."
}

run_installer() {
  ensure_host_tools
  ensure_cache_dir
  validate_state_path
  install -d -m 0755 "$STATE_DIR"
  local iso boot_dir os_disk data_disk install_log boot_log pidfile install_marker source_stage source_id marker_id options pid
  local persistent_mode="${NAS_QEMU_PERSISTENT_MODE:-0}"
  local reuse_installed="${NAS_QEMU_REUSE_INSTALLED:-0}"
  local ssh_key ssh_key_dir full_suite_skip_fuzz
  local -a accel network_args ssh_args
  os_disk="$STATE_DIR/nixos-nas-os.qcow2"
  data_disk="$STATE_DIR/nixos-nas-zfs.qcow2"
  install_log="$STATE_DIR/installer-console.log"
  boot_log="$STATE_DIR/installed-console.log"
  pidfile="$STATE_DIR/qemu.pid"
  install_marker="$STATE_DIR/os-install-complete"
  ssh_key="$STATE_DIR/installer-admin-ed25519"
  ssh_key_dir="$STATE_DIR/ssh-key"

  cleanup_vm() {
    local cleanup_pidfile="$STATE_DIR/qemu.pid"
    nas_qemu_cleanup_pidfile "$cleanup_pidfile" 20 || {
      local pid_status=$?
      (( pid_status == 2 )) && die "refusing to clean up a pidfile owned by a non-QEMU process: $cleanup_pidfile"
      return "$pid_status"
    }
  }
  trap cleanup_vm EXIT INT TERM

  source_stage="$(stage_source_tree)"
  source_id="$(source_fingerprint "$source_stage")"
  marker_id="$(cat "$install_marker" 2>/dev/null || true)"

  if [[ "$persistent_mode" == 1 && "${NAS_QEMU_PERSISTENT_ACTION:-start}" == test \
    && -s "$os_disk" && -s "$data_disk" && -s "$ssh_key" && -s "$install_marker" ]]; then
    restore_persistent_baseline "$os_disk" "$data_disk"
    rm -f "$boot_log"
  fi

  if [[ "$persistent_mode" != 1 || ! -s "$pidfile" ]]; then
    rm -f "$pidfile"
  elif nas_qemu_pid_from_pidfile "$pidfile"; then
    :
  else
    local pid_status=$?
    (( pid_status == 2 )) && die "refusing to reuse a pidfile owned by a non-QEMU process: $pidfile"
    rm -f "$pidfile"
  fi
  rm -f "$install_log"
  if [[ "$persistent_mode" != 1 || ! -s "$pidfile" ]]; then
    rm -f "$boot_log"
  fi
  if [[ "$reuse_installed" != 1 && ( "$KEEP_VM" != 1 || ! -s "$os_disk" || ! -s "$ssh_key" || "$marker_id" != "$source_id" ) ]] || \
     [[ ! -s "$os_disk" || ! -s "$ssh_key" || ! -s "$install_marker" ]]; then
    iso="$(download_iso)"
    boot_dir="$(extract_iso_boot "$iso")"
    rm -f "$os_disk" "$data_disk" "$install_marker" "$ssh_key" "$ssh_key.pub"
    rm -rf "$ssh_key_dir"
    install -d -m 0700 "$ssh_key_dir"
    ssh-keygen -q -t ed25519 -N '' -C 'nixos-nas-qemu-ephemeral' -f "$ssh_key"
    install -m 0644 "$ssh_key.pub" "$ssh_key_dir/admin.pub"
    qemu-img create -q -f qcow2 "$os_disk" "${OS_DISK_GIB}G"
    qemu-img create -q -f qcow2 "$data_disk" "${DATA_DISK_GIB}G"

    mapfile -t accel < <(qemu_acceleration)
    mapfile -t network_args < <(qemu_network_args)
    options="$(cat "$boot_dir/options") console=ttyS0,115200n8 systemd.show_status=1"
    log "Installing NixOS NAS into a fresh QEMU disk"
    expect "$ROOT/tests/vm/install.expect" \
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
      "${network_args[@]}" \
      -pidfile "$pidfile" \
      -no-reboot -nographic 2>&1 | tee "$install_log"
    if [[ "$persistent_mode" == 1 ]]; then
      qemu-img snapshot -c "$BASELINE_SNAPSHOT" "$os_disk"
      qemu-img snapshot -c "$BASELINE_SNAPSHOT" "$data_disk"
    fi
    printf '%s\n' "$source_id" > "$install_marker"
  else
    log "Reusing the installed OS disk for the persistent wrapper"
  fi

  if [[ "$persistent_mode" != 1 || ! -s "$data_disk" ]]; then
    rm -f "$data_disk"
    qemu-img create -q -f qcow2 "$data_disk" "${DATA_DISK_GIB}G"
  fi

  mapfile -t accel < <(qemu_acceleration)
  mapfile -t network_args < <(qemu_network_args)
  if [[ ! -s "$pidfile" ]]; then
    log "Booting installed NAS in a disposable QEMU VM"
  elif nas_qemu_pid_from_pidfile "$pidfile"; then
    log "Persistent QEMU VM is already running (pid $(<"$pidfile"))"
  else
    local pid_status=$?
    (( pid_status == 2 )) && die "refusing to reuse a pidfile owned by a non-QEMU process: $pidfile"
    rm -f "$pidfile"
    log "Booting installed NAS in a disposable QEMU VM"
  fi
  if [[ ! -s "$pidfile" ]]; then
    qemu-system-x86_64 \
      "${accel[@]}" \
      -m "$MEMORY_MIB" -smp "$CPUS" \
      -drive "file=$os_disk,format=qcow2,if=virtio" \
      -drive "file=$data_disk,format=qcow2,if=virtio" \
      -device virtio-rng-pci \
      "${network_args[@]}" \
      -display none -serial "file:$boot_log" -daemonize -pidfile "$pidfile"
  fi

  mapfile -t ssh_args < <(ssh_options "$ssh_key")
  if ! wait_for_ssh "$ssh_key"; then
    cat "$boot_log" >&2 || true
    die "installed VM did not become reachable over SSH on port $SSH_PORT"
  fi

  if [[ "$persistent_mode" == 1 ]]; then
    # Once SSH proves that the daemonized VM is healthy, persistent-start owns
    # its lifecycle and must not let this process's EXIT trap stop it.
    nas_qemu_disarm_cleanup
    full_suite_skip_fuzz="${NAS_QEMU_SKIP_FUZZ:-0}"
    sync_source_to_guest "$source_stage" "$ssh_key"
    if [[ "${NAS_QEMU_PERSISTENT_ACTION:-start}" == test || "$marker_id" != "$source_id" ]]; then
      rebuild_guest_source "$ssh_key"
      printf '%s\n' "$source_id" > "$install_marker"
    fi
    # Leave a failed persistent run available for inspection. The explicit
    # stop/reset wrappers own its lifecycle and can remove it deliberately.
    if [[ "${NAS_QEMU_PERSISTENT_ACTION:-start}" == test ]]; then
      log "Running the complete source and appliance suite inside the persistent VM"
      timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
        "${NAS_QEMU_SOURCE_SUITE_TIMEOUT:-$(nas_vm_full_suite_timeout_seconds)}" \
        ssh "${ssh_args[@]}" \
          -o ServerAliveInterval=15 -o ServerAliveCountMax=20 \
          -p "$SSH_PORT" admin@127.0.0.1 \
          "cd /var/lib/nas-test/repo &&
           sudo -n systemctl reset-failed &&
           sudo -n nas-secrets stop &&
           sudo -n env NAS_FULL_SUITE_REPO=/var/lib/nas-test/repo NAS_FULL_SUITE_SKIP_FUZZ=$full_suite_skip_fuzz \
             nix develop path:/var/lib/nas-test/repo#test -c \
             bash /var/lib/nas-test/repo/tests/vm/full-suite.sh"
    fi
    log "Persistent VM is ready; use scripts/vm-pytest.sh or scripts/vm-stop.sh."
    return 0
  fi

  timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "${NAS_QEMU_GUEST_TEST_TIMEOUT:-$(nas_vm_guest_watchdog_seconds)}" \
    ssh "${ssh_args[@]}" \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=20 \
      -p "$SSH_PORT" admin@127.0.0.1 \
      "sudo -n env NAS_TEST_TIMEOUT=$(nas_vm_ordinary_wait_seconds) nas-vm-guest-test /dev/vdb"

  log "Exercising post-install activation, failed-candidate, and rollback paths"
  timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "${NAS_QEMU_RECONFIGURE_TIMEOUT:-$(nas_vm_timeout_value reconfigure)}" \
    ssh "${ssh_args[@]}" \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=20 \
      -p "$SSH_PORT" admin@127.0.0.1 \
      "sudo -n env NAS_TEST_REBUILD_TIMEOUT=$(nas_vm_timeout_value reconfigureBuild) nas-vm-reconfigure-test"

  ssh "${ssh_args[@]}" \
    -p "$SSH_PORT" admin@127.0.0.1 'sudo -n poweroff' >/dev/null 2>&1 || true
  if [[ -s "$pidfile" ]]; then
    if nas_qemu_pid_from_pidfile "$pidfile"; then
      pid="$QEMU_PID"
      for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    else
      local pid_status=$?
      (( pid_status == 2 )) && die "refusing to wait on a pidfile owned by a non-QEMU process: $pidfile"
    fi
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
    "${network_args[@]}" \
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
    if nas_qemu_pid_from_pidfile "$pidfile"; then
      pid="$QEMU_PID"
      for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    else
      local pid_status=$?
      (( pid_status == 2 )) && die "refusing to wait on a pidfile owned by a non-QEMU process: $pidfile"
    fi
  fi
  trap - EXIT INT TERM
  cleanup_vm
  log "Installed-VM test completed successfully"
}

run_installer_with_timeout() {
  local mode=$1 timeout_seconds
  case "$mode" in
    persistent-test) timeout_seconds="${NAS_QEMU_FULL_SUITE_TIMEOUT:-$(nas_vm_full_suite_timeout_seconds)}" ;;
    *) timeout_seconds="${NAS_QEMU_INSTALLER_TIMEOUT:-$(nas_vm_installer_timeout_seconds)}" ;;
  esac
  if [[ "${NAS_QEMU_OUTER_TIMEOUT_ACTIVE:-0}" == 1 ]]; then
    run_installer
  else
    NAS_QEMU_OUTER_TIMEOUT_ACTIVE=1 \
      timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
      "$timeout_seconds" "$0" "$mode"
  fi
}

case "$MODE" in
  static) run_static ;;
  native) run_native ;;
  installer) run_installer_with_timeout installer ;;
  persistent-start)
    export NAS_QEMU_PERSISTENT_MODE=1 NAS_QEMU_PERSISTENT_ACTION=start NAS_QEMU_REUSE_INSTALLED=1
    run_installer_with_timeout persistent-start
    ;;
  persistent-test)
    export NAS_QEMU_PERSISTENT_MODE=1 NAS_QEMU_PERSISTENT_ACTION=test NAS_QEMU_REUSE_INSTALLED=1
    run_installer_with_timeout persistent-test
    ;;
  persistent-stop) validate_state_path; stop_persistent_vm ;;
  persistent-reset) reset_persistent_state ;;
  stage-source)
    ensure_cache_dir
    validate_state_path
    stage_source_tree "${NAS_QEMU_SOURCE_ROOT:-$ROOT}"
    ;;
  all) run_static; run_native; run_installer_with_timeout installer ;;
  clean)
    require_cache_marker
    validate_state_path
    stop_persistent_vm
    rm -rf -- "$CACHE_DIR"
    log "Removed $CACHE_DIR"
    ;;
  -h|--help|help) usage ;;
  *) usage >&2; die "unknown mode: $MODE" ;;
esac
