#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
CACHE_DIR="${NAS_QEMU_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/nixos-nas-qemu}"
STATE_DIR="${NAS_QEMU_STATE_DIR:-$CACHE_DIR/state}"
SSH_PORT="${NAS_QEMU_SSH_PORT:-2222}"
KEY="$STATE_DIR/installer-admin-ed25519"

[[ -s "$KEY" ]] || { printf 'error: VM key not found at %s; run scripts/vm-start.sh first\n' "$KEY" >&2; exit 1; }

exec ssh \
  -i "$KEY" \
  -o IdentitiesOnly=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -p "$SSH_PORT" \
  admin@127.0.0.1 \
  "$@"