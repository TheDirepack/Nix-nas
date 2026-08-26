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

SSH_PORT="${NAS_QEMU_SSH_PORT:-2222}"
HTTPS_PORT="${NAS_QEMU_HTTPS_PORT:-8443}"
KEY="${NAS_QEMU_STATE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/nixos-nas-qemu/state}/installer-admin-ed25519"
ssh_vm() {
  ssh -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -p "$SSH_PORT" admin@127.0.0.1 "$@"
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
for _ in $(seq 1 30); do
  code="$(curl -ksS -o /dev/null -w '%{http_code}' \
    --resolve "nas-test.local:${HTTPS_PORT}:127.0.0.1" \
    "https://nas-test.local:${HTTPS_PORT}/console/" || true)"
  [[ "$code" == 302 || "$code" == 200 ]] && break
  sleep 2
done

cat <<EOF

VM ready for interactive testing:
  Launcher/setup : https://nas-test.local:${HTTPS_PORT}/
  Authentik      : https://nas-test.local:${HTTPS_PORT}/identity/
  Cockpit console: https://nas-test.local:${HTTPS_PORT}/console/

Pre-setup bootstrap sign-in (retired after first-run setup completes):
  akadmin / nas-admin-first-boot

Guest shell: scripts/vm-run.sh '<command>'
EOF
