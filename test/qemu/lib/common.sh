#!/usr/bin/env bash
# Shared configuration and helpers for the QEMU/NixOS test harness.
#
# Everything here is overridable via environment variables so the harness can
# be tuned per-host without editing files:
#   QEMU_ISO      path to the NixOS minimal ISO
#   VM_MEM        VM RAM in MiB            (default 4096)
#   VM_CPUS       VM vCPUs                 (default 4)
#   VM_DISK_SIZE  qcow2 size               (default 40G)
#   VM_SSH_PORT   host-forwarded SSH port  (default 2222)
#   QEMU_BIN      qemu binary              (default qemu-system-x86_64)
#   FIRMWARE      bios | uefi              (default bios)
set -euo pipefail

QEMU_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="$(cd -- "$QEMU_DIR/../.." && pwd)"

STATE_DIR="$QEMU_DIR/state"
BOOT_DIR="$STATE_DIR/boot"
LOG_DIR="$STATE_DIR/logs"
KEY_DIR="$STATE_DIR/keys"

ISO="${QEMU_ISO:-/tmp/opencode/qemu/nixos-minimal-x86_64.iso}"
DISK="$STATE_DIR/nas-vm.qcow2"
DISK_SIZE="${VM_DISK_SIZE:-40G}"
PROVISION_IMG="$STATE_DIR/provisioning.img"
PROVISION_DIR="$STATE_DIR/provision"
SERIAL_SOCK="$STATE_DIR/serial.sock"
VM_PIDFILE="$STATE_DIR/vm.pid"
INSTALL_MARKER="$STATE_DIR/installed"

SSH_PORT="${VM_SSH_PORT:-2222}"
VM_MEM="${VM_MEM:-4096}"
VM_CPUS="${VM_CPUS:-4}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
FIRMWARE="${FIRMWARE:-bios}"

HARNESS_KEY="$KEY_DIR/harness-key"
HARNESS_KEY_PUB="$KEY_DIR/harness-key.pub"

SSH_ARGS="-p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 -i $HARNESS_KEY"

OVMF_CODE="${OVMF_CODE:-/usr/share/edk2/x64/OVMF_CODE.4m.fd}"
OVMF_VARS="$STATE_DIR/OVMF_VARS.4m.fd"

# --- logging ---------------------------------------------------------------

log() { printf '\033[1;34m[harness]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[harness]\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[1;31m[harness]\033[0m ERROR: %s\n' "$*" >&2
  exit 1
}

# --- helpers ---------------------------------------------------------------

need_cmd() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found on host: $c"
  done
}

ensure_dirs() {
  mkdir -p "$BOOT_DIR" "$LOG_DIR" "$KEY_DIR" "$PROVISION_DIR"
}

ensure_iso() {
  [ -f "$ISO" ] || die "ISO not found: $ISO (set QEMU_ISO)"
}

ensure_keys() {
  if [ ! -f "$HARNESS_KEY" ]; then
    log "Generating harness SSH key ($HARNESS_KEY)"
    ssh-keygen -t ed25519 -N "" -f "$HARNESS_KEY" -C "qemu-nas-harness" >/dev/null 2>&1
  fi
  chmod 600 "$HARNESS_KEY"
}

ensure_disk() {
  if [ ! -f "$DISK" ]; then
    log "Creating qcow2 VM disk ($DISK_SIZE): $DISK"
    qemu-img create -f qcow2 -o preallocation=off "$DISK" "$DISK_SIZE"
  fi
}

vm_running() {
  [ -f "$VM_PIDFILE" ] || return 1
  local pid
  pid="$(cat "$VM_PIDFILE" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

vm_pid() {
  [ -f "$VM_PIDFILE" ] && cat "$VM_PIDFILE" 2>/dev/null || true
}

# wait_for_ssh <timeout-seconds>
# Blocks until the VM's SSH port answers as the harness root user, or dies.
wait_for_ssh() {
  local timeout="${1:-240}"
  local deadline=$(( $(date +%s) + timeout ))
  log "Waiting up to ${timeout}s for SSH on 127.0.0.1:$SSH_PORT ..."
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if ssh $SSH_ARGS root@127.0.0.1 true >/dev/null 2>&1; then
      log "SSH is up."
      return 0
    fi
    sleep 3
  done
  warn "SSH did not come up within ${timeout}s."
  return 1
}
