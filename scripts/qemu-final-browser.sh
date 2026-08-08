#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="${NAS_QEMU_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/nixos-nas-qemu}"
STATE_DIR="${NAS_QEMU_STATE_DIR:-$CACHE_DIR/state}"
SSH_PORT="${NAS_QEMU_SSH_PORT:-2222}"
HTTP_PORT="${NAS_QEMU_HTTP_PORT:-8088}"
HTTPS_PORT="${NAS_QEMU_HTTPS_PORT:-8443}"
COCKPIT_PORT="${NAS_QEMU_COCKPIT_PORT:-9094}"
MEMORY_MIB="${NAS_QEMU_MEMORY_MIB:-10240}"
CPUS="${NAS_QEMU_CPUS:-4}"
TEST_USER="${NAS_VM_TEST_USER:-nas-browser-test}"
TEST_PASSWORD="${NAS_VM_TEST_PASSWORD:-NasBrowser-${GITHUB_RUN_ID:-local}-${RANDOM}!}"
OS_DISK="$STATE_DIR/nixos-nas-os.qcow2"
SSH_KEY="$STATE_DIR/installer-admin-ed25519"
OVERLAY="$STATE_DIR/browser-os-overlay.qcow2"
DATA_DISK="$STATE_DIR/browser-data.qcow2"
PIDFILE="$STATE_DIR/browser-qemu.pid"
BOOT_LOG="$STATE_DIR/browser-console.log"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

for cmd in qemu-system-x86_64 qemu-img ssh curl npm; do need "$cmd"; done
[[ "$TEST_USER" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || die "invalid NAS_VM_TEST_USER"
[[ -s "$OS_DISK" ]] || die "installed VM disk is missing; run qemu-test.sh installer first"
[[ -s "$SSH_KEY" ]] || die "installer SSH key is missing; run qemu-test.sh installer first"

cleanup() {
  if [[ -s "$PIDFILE" ]]; then
    pid="$(cat "$PIDFILE")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$PIDFILE" "$OVERLAY" "$DATA_DISK"
}
trap cleanup EXIT INT TERM
cleanup

qemu-img create -q -f qcow2 -F qcow2 -b "$OS_DISK" "$OVERLAY"
qemu-img create -q -f qcow2 "$DATA_DISK" 8G

accel=(-machine accel=tcg -cpu max)
if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
  accel=(-enable-kvm -cpu host)
fi

log "Booting disposable overlay of the verified installed NAS"
qemu-system-x86_64 \
  "${accel[@]}" \
  -m "$MEMORY_MIB" -smp "$CPUS" \
  -drive "file=$OVERLAY,format=qcow2,if=virtio" \
  -drive "file=$DATA_DISK,format=qcow2,if=virtio" \
  -device virtio-rng-pci \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$HTTP_PORT-:80,hostfwd=tcp:127.0.0.1:$HTTPS_PORT-:443,hostfwd=tcp:127.0.0.1:$COCKPIT_PORT-:9092" \
  -device virtio-net-pci,netdev=net0 \
  -display none -serial "file:$BOOT_LOG" -daemonize -pidfile "$PIDFILE"

ssh_args=(
  -i "$SSH_KEY"
  -o IdentitiesOnly=yes
  -o PasswordAuthentication=no
  -o KbdInteractiveAuthentication=no
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=2
  -p "$SSH_PORT"
)

for _ in $(seq 1 180); do
  if ssh "${ssh_args[@]}" admin@127.0.0.1 true >/dev/null 2>&1; then break; fi
  sleep 2
done
ssh "${ssh_args[@]}" admin@127.0.0.1 true >/dev/null 2>&1 || {
  cat "$BOOT_LOG" >&2 || true
  die "final browser VM did not become reachable over SSH"
}

log "Creating an overlay-only Cockpit test identity"
ssh "${ssh_args[@]}" admin@127.0.0.1 \
  "sudo -n id -u '$TEST_USER' >/dev/null 2>&1 || sudo -n useradd --create-home --groups wheel --shell /bin/bash '$TEST_USER'"
printf '%s:%s\n' "$TEST_USER" "$TEST_PASSWORD" | \
  ssh "${ssh_args[@]}" admin@127.0.0.1 'sudo -n chpasswd'

for _ in $(seq 1 90); do
  if curl --fail --insecure --silent --show-error "https://127.0.0.1:$COCKPIT_PORT/" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl --fail --insecure --silent --show-error "https://127.0.0.1:$COCKPIT_PORT/" >/dev/null || die "Cockpit did not become reachable"

# Deterministic regression probes intentionally run before any active fuzzer.
# This makes common auth/XSS/layout/accessibility regressions cheap to identify
# and ensures long-running fuzz results are not hiding a basic known failure.
log "Running deterministic authenticated and unauthenticated browser checks against the final VM"
CI=1 \
NAS_BROWSER_SUITE=vm \
NAS_VM_BASE_URL="https://127.0.0.1:$COCKPIT_PORT" \
NAS_VM_TEST_USER="$TEST_USER" \
NAS_VM_TEST_PASSWORD="$TEST_PASSWORD" \
npm --prefix "$ROOT/cockpit" exec -- playwright test --config e2e/playwright.config.mjs

if [[ -n "${NAS_ZAP_IMAGE:-}" && "${NAS_FINAL_VM_FUZZ:-1}" == 1 ]]; then
  fuzz_out="${NAS_ZAP_OUT_DIR:-$ROOT/zap-report}/final-vm"
  install -d -m 0755 "$fuzz_out"
  log "Running state-aware unauthenticated ZAP Client Spider and active scan"
  NAS_ZAP_OUT_DIR="$fuzz_out" \
    bash "$ROOT/scripts/zap-automation-scan.sh" unauthenticated "https://127.0.0.1:$COCKPIT_PORT/"

  log "Running state-aware authenticated ZAP Client Spider and active scan"
  NAS_ZAP_OUT_DIR="$fuzz_out" \
  NAS_ZAP_AUTH_USER="$TEST_USER" \
  NAS_ZAP_AUTH_PASSWORD="$TEST_PASSWORD" \
    bash "$ROOT/scripts/zap-automation-scan.sh" authenticated "https://127.0.0.1:$COCKPIT_PORT/"
else
  log "Skipping final-VM active fuzzing because NAS_ZAP_IMAGE is unset or NAS_FINAL_VM_FUZZ is disabled"
fi

log "Final installed-VM deterministic and fuzz checks passed"
