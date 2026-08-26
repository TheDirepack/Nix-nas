#!/usr/bin/env bash
# shellcheck disable=SC2317
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/nas-qemu-process.sh"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
fake_qemu="$work/qemu-system-x86_64"
cp -- "$(command -v sleep)" "$fake_qemu"

start_fake_qemu() {
  # Model the detached persistent VM rather than a shell-owned background job.
  # Redirect all stdio and start a new session so leaving the launching subshell
  # cannot terminate the fake QEMU before the cleanup contract inspects it.
  setsid "$fake_qemu" 60 </dev/null >/dev/null 2>&1 &
  printf '%s\n' "$!" > "$1"
  if (($# > 1)); then
    printf '%s\n' "$!" > "$2"
  fi
}

assert_running() {
  kill -0 "$(<"$1")" 2>/dev/null
}

failure_pidfile="$work/failure.pid"
set +e
(
  set -Eeuo pipefail
  # shellcheck disable=SC2329
  cleanup() {
    local status=$?
    nas_qemu_cleanup_pidfile "$failure_pidfile" 1 || true
    return "$status"
  }
  trap cleanup EXIT INT TERM
  start_fake_qemu "$failure_pidfile" "$work/failure.process"
  assert_running "$failure_pidfile"
  exit 97
)
failure_status=$?
set -e
[[ "$failure_status" -eq 97 ]]
if kill -0 "$(<"$work/failure.process")" 2>/dev/null; then
  exit 1
fi
[[ ! -e "$failure_pidfile" ]]

persistent_pidfile="$work/persistent.pid"
(
  set -Eeuo pipefail
  # shellcheck disable=SC2329
  cleanup() {
    local status=$?
    nas_qemu_cleanup_pidfile "$persistent_pidfile" 1 || true
    return "$status"
  }
  trap cleanup EXIT INT TERM
  start_fake_qemu "$persistent_pidfile"
  assert_running "$persistent_pidfile"
  nas_qemu_disarm_cleanup
)
assert_running "$persistent_pidfile"
nas_qemu_cleanup_pidfile "$persistent_pidfile" 1
[[ ! -e "$persistent_pidfile" ]]

printf '%s\n' "Persistent QEMU lifecycle contract passed"
