#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

usage() {
  cat <<'USAGE'
Usage: scripts/vm-dev.sh

Start (or reuse) the persistent NixOS QEMU VM for interactive browser
testing, refresh the current worktree into it, wait until the browser-facing
services are ready, and print the testing URLs.

This wraps scripts/vm-start.sh; use vm-pytest.sh for the full in-guest suite,
vm-stop.sh to stop, and vm-reset.sh to discard the installed disk.
USAGE
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) usage >&2; exit 2 ;;
esac

log() { printf '==> %s\n' "$*" >&2; }

log "Starting the persistent VM (installs on first use)"
"$ROOT/scripts/vm-start.sh"

HTTPS_PORT="${NAS_QEMU_HTTPS_PORT:-8443}"
ssh_vm() {
  "$ROOT/scripts/vm-run.sh" "$@"
}

log "Waiting for Authentik, the proxy outpost, Caddy, and Cockpit SSO"
ready=0
for _ in $(seq 1 90); do
  state="$(ssh_vm 'systemctl is-active caddy authentik nas-cockpit-sso nas-authentik-proxy-outpost' 2>/dev/null | tr '\n' ' ' || true)"
  if [[ "$state" == *"active active active active"* ]]; then
    ready=1
    break
  fi
  sleep 3
done
if [[ "$ready" != 1 ]]; then
  log "Services did not become active; inspect with: scripts/vm-run.sh 'systemctl --failed'"
  exit 1
fi

log "Probing the Console redirect through Caddy"
ready=0
for _ in $(seq 1 30); do
  curl_status=0
  # Capture the transport status without letting `set -e` abort the script when
  # the Console is not reachable yet (curl exits non-zero and reports 000).
  code="$(curl -ksS -o /dev/null -w '%{http_code}' \
    --noproxy '*' \
    --resolve "nas-test.local:${HTTPS_PORT}:127.0.0.1" \
    "https://nas-test.local:${HTTPS_PORT}/console/")" || curl_status=$?
  if (( curl_status == 0 )) && [[ "$code" == 302 || "$code" == 200 ]]; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then
  log "Console did not become ready; inspect Caddy and Cockpit SSO"
  exit 1
fi

cat <<EOF

VM ready for interactive testing:
  Launcher/setup : https://nas-test.local:${HTTPS_PORT}/
  Authentik      : https://nas-test.local:${HTTPS_PORT}/identity/
  Cockpit console: https://nas-test.local:${HTTPS_PORT}/console/

Pre-setup bootstrap sign-in (retired after first-run setup completes):
  akadmin / nas-admin-first-boot

Guest shell: scripts/vm-run.sh '<command>'
EOF
