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
WORKLOAD="${NAS_FINAL_VM_WORKLOAD:-deterministic-browser}"
OS_DISK="$STATE_DIR/nixos-nas-os.qcow2"
SSH_KEY="$STATE_DIR/installer-admin-ed25519"
OVERLAY="$STATE_DIR/browser-os-overlay.qcow2"
DATA_DISK="$STATE_DIR/browser-data.qcow2"
PIDFILE="$STATE_DIR/browser-qemu.pid"
BOOT_LOG="$STATE_DIR/browser-console.log"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

for cmd in qemu-system-x86_64 qemu-img ssh curl python3; do need "$cmd"; done
[[ "$WORKLOAD" =~ ^(deterministic-browser|installed-command-fuzz|zap-fuzz)$ ]] || die "invalid NAS_FINAL_VM_WORKLOAD"
if [[ "$WORKLOAD" == deterministic-browser ]]; then need npm; fi
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

if [[ "$WORKLOAD" != installed-command-fuzz ]]; then
  log "Creating an overlay-only Cockpit test identity"
  printf '%s\n' "$TEST_USER" | \
    ssh "${ssh_args[@]}" admin@127.0.0.1 \
      'IFS= read -r test_user; sudo -n id -u "$test_user" >/dev/null 2>&1 || sudo -n useradd --create-home --groups wheel --shell /bin/bash "$test_user"'
  printf '%s:%s\n' "$TEST_USER" "$TEST_PASSWORD" | \
    ssh "${ssh_args[@]}" admin@127.0.0.1 'sudo -n chpasswd'
fi

for _ in $(seq 1 90); do
  if curl --fail --insecure --silent --show-error "https://127.0.0.1:$COCKPIT_PORT/" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl --fail --insecure --silent --show-error "https://127.0.0.1:$COCKPIT_PORT/" >/dev/null || die "Cockpit did not become reachable"

run_http_adversarial_contracts() {
  local evidence=${1:?evidence path is required}
  local body code label url path
  local requests=0 blocked=0
  body="$(mktemp "${TMPDIR:-/tmp}/nas-http-adversarial.XXXXXX")"
  trap 'rm -f -- "$body"' RETURN

  probe_not_5xx() {
    label=$1
    url=$2
    shift 2
    code="$(curl --insecure --silent --show-error --output "$body" --write-out '%{http_code}' \
      --connect-timeout 5 --max-time 20 "$@" "$url" || true)"
    [[ "$code" =~ ^[0-9]{3}$ ]] || die "$label did not return an HTTP status"
    [[ "$code" != 5* ]] || {
      cat "$body" >&2 || true
      die "$label returned server error HTTP $code"
    }
    requests=$((requests + 1))
  }

  probe_blocked() {
    path=$1
    code="$(curl --insecure --silent --show-error --output "$body" --write-out '%{http_code}' \
      --connect-timeout 5 --max-time 20 \
      --resolve "nas-test.local:$HTTPS_PORT:127.0.0.1" \
      -H 'Remote-User: akadmin' \
      -H 'Remote-Groups: nas_admin,nas_allow_files,nas_allow_ai' \
      -H 'X-authentik-username: akadmin' \
      -H 'X-authentik-groups: nas_admin' \
      "https://nas-test.local:$HTTPS_PORT$path" || true)"
    case "$code" in
      301|302|303|307|308|401|403|404) ;;
      *)
        cat "$body" >&2 || true
        die "spoofed identity headers reached protected path $path (HTTP ${code:-none})"
        ;;
    esac
    requests=$((requests + 1))
    blocked=$((blocked + 1))
  }

  log "Running curl-based HTTP adversarial contracts"
  probe_not_5xx "Cockpit hostile query" \
    "https://127.0.0.1:$COCKPIT_PORT/?q=%3Cscript%3EglobalThis.__nas_xss%3D1%3C%2Fscript%3E"
  probe_not_5xx "Cockpit encoded traversal" \
    "https://127.0.0.1:$COCKPIT_PORT/%2e%2e/%2e%2e/etc/passwd" --path-as-is
  probe_not_5xx "Caddy hostile query" \
    "https://nas-test.local:$HTTPS_PORT/?q=%3Csvg%2Fonload%3Dalert%281%29%3E" \
    --resolve "nas-test.local:$HTTPS_PORT:127.0.0.1"
  probe_not_5xx "Caddy encoded traversal" \
    "https://nas-test.local:$HTTPS_PORT/%2e%2e/%2e%2e/etc/shadow" \
    --resolve "nas-test.local:$HTTPS_PORT:127.0.0.1" --path-as-is

  for path in /shares/ /shares/admin/ /console/ /ai/ /syncthing/ /vault/admin /metrics/ /alerts/; do
    probe_blocked "$path"
  done

  install -d -m 0755 "$(dirname "$evidence")"
  python3 - "$evidence" "$requests" "$blocked" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = {
    "ok": True,
    "engine": "curl",
    "requests": int(sys.argv[2]),
    "spoofedIdentityPathsBlocked": int(sys.argv[3]),
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

case "$WORKLOAD" in
  deterministic-browser)
    log "Running deterministic authenticated and unauthenticated browser checks against the final VM"
    CI=1 \
    NAS_BROWSER_SUITE=vm \
    NAS_VM_BASE_URL="https://127.0.0.1:$COCKPIT_PORT" \
    NAS_VM_TEST_USER="$TEST_USER" \
    NAS_VM_TEST_PASSWORD="$TEST_PASSWORD" \
    npm --prefix "$ROOT/cockpit" exec -- playwright test --config e2e/playwright.config.mjs
    ;;
  installed-command-fuzz)
    fuzz_out="${NAS_INSTALLED_FUZZ_OUT:-$ROOT/installed-command-fuzz.json}"
    http_out="${NAS_HTTP_ADVERSARIAL_OUT:-$ROOT/http-adversarial.json}"
    install -d -m 0755 "$(dirname "$fuzz_out")"
    log "Running installed-command adversarial fuzzing in the disposable VM"
    ssh "${ssh_args[@]}" admin@127.0.0.1 \
      'sudo -n python3 /var/lib/nas-test/repo/tests/vm/adversarial-installed.py' >"$fuzz_out"
    python3 - "$ROOT/tests/custom-script-contracts.json" "$fuzz_out" <<'PY'
import json
import pathlib
import sys

contracts = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
result = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
expected = sum(item.get("fuzzStrategy") is not None for item in contracts["executables"])
if result.get("ok") is not True or result.get("commands") != expected or expected == 0:
    raise SystemExit("installed-command fuzz evidence is empty or incomplete")
PY
    run_http_adversarial_contracts "$http_out"
    ;;
  zap-fuzz)
    [[ -n "${NAS_ZAP_IMAGE:-}" ]] || die "NAS_ZAP_IMAGE is required for zap-fuzz"
    fuzz_out="${NAS_ZAP_OUT_DIR:-$ROOT/zap-report}/final-vm"
    install -d -m 0755 "$fuzz_out"
    scan_mode="${NAS_ZAP_MODE:-baseline}"
    log "Running public and Cockpit ZAP $scan_mode scans"
    NAS_ZAP_OUT_DIR="$fuzz_out" \
    NAS_ZAP_EXTRA_HOST="nas-test.local:127.0.0.1" \
    NAS_ZAP_REPORT_PREFIX="public" \
      bash "$ROOT/scripts/zap-scan.sh" "$scan_mode" "https://nas-test.local:$HTTPS_PORT/"
    NAS_ZAP_OUT_DIR="$fuzz_out" \
    NAS_ZAP_REPORT_PREFIX="cockpit" \
      bash "$ROOT/scripts/zap-scan.sh" "$scan_mode" "https://127.0.0.1:$COCKPIT_PORT/"
    log "Running state-aware unauthenticated ZAP Client Spider and active scan"
    NAS_ZAP_OUT_DIR="$fuzz_out" \
      bash "$ROOT/scripts/zap-automation-scan.sh" unauthenticated "https://127.0.0.1:$COCKPIT_PORT/"
    log "Running state-aware authenticated ZAP Client Spider and active scan"
    NAS_ZAP_OUT_DIR="$fuzz_out" \
    NAS_ZAP_AUTH_USER="$TEST_USER" \
    NAS_ZAP_AUTH_PASSWORD="$TEST_PASSWORD" \
      bash "$ROOT/scripts/zap-automation-scan.sh" authenticated "https://127.0.0.1:$COCKPIT_PORT/"
    ;;
esac

log "Final installed-VM $WORKLOAD workload passed"
