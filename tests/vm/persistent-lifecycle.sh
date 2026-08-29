#!/usr/bin/env bash
# shellcheck disable=SC2317
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/nas-qemu-process.sh"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
fake_qemu="$work/qemu-system-x86_64"
fake_qemu_input="$work/qemu-input"
# Nix coreutils uses multicall binaries that can dispatch by argv[0], so a
# renamed copy of `sleep` is not a stable fake QEMU. Bash does not have that
# behavior. Block the copied Bash executable on a FIFO so /proc/$pid/exe keeps
# the exact qemu-system-x86_64 basename that the production cleanup validates.
cp -- "$(readlink -f "$(command -v bash)")" "$fake_qemu"
mkfifo "$fake_qemu_input"
exec {fake_qemu_hold_fd}<>"$fake_qemu_input"

wait_for_fake_qemu_exec() {
  local pid=$1 executable
  for _ in $(seq 1 200); do
    kill -0 "$pid" 2>/dev/null || break
    executable="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
    if [[ "${executable##*/}" == qemu-system-x86_64 ]]; then
      return 0
    fi
    sleep 0.01
  done
  executable="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  printf 'fake QEMU pid %s did not exec expected binary; executable=%s\n' \
    "$pid" "${executable:-<exited>}" >&2
  return 1
}

start_fake_qemu() {
  local pid
  "$fake_qemu" -c 'IFS= read -r _' <"$fake_qemu_input" >/dev/null 2>&1 &
  pid=$!
  if ! wait_for_fake_qemu_exec "$pid"; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
  fi
  printf '%s\n' "$pid" > "$1"
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
  start_fake_qemu "$failure_pidfile"
  assert_running "$failure_pidfile"
  exit 97
)
failure_status=$?
set -e
[[ "$failure_status" -eq 97 ]] || {
  printf 'failure-path fixture returned %s instead of 97\n' "$failure_status" >&2
  exit 1
}
# The production cleanup helper removes the owned pidfile only after validating
# the executable identity and completing its TERM/KILL/wait path. Checking that
# authority is deterministic; checking the raw numeric pid from the parent
# shell is not, because that pid may already have been recycled by the runner.
[[ ! -e "$failure_pidfile" ]] || {
  printf 'failure-path pidfile survived armed cleanup\n' >&2
  exit 1
}

# Keep the persistent process as a direct child of this shell. The contract we
# need to prove here is that cleanup is armed during startup, is disarmed only
# after the process is healthy, and explicit cleanup still works afterwards.
persistent_pidfile="$work/persistent.pid"
# shellcheck disable=SC2329
persistent_cleanup() {
  local status=$?
  nas_qemu_cleanup_pidfile "$persistent_pidfile" 1 || true
  rm -rf -- "$work"
  return "$status"
}
trap persistent_cleanup EXIT INT TERM
start_fake_qemu "$persistent_pidfile"
assert_running "$persistent_pidfile"
nas_qemu_disarm_cleanup
if [[ -n "$(trap -p EXIT INT TERM)" ]]; then
  printf 'persistent cleanup traps remained armed after disarm\n' >&2
  exit 1
fi
# Restore only the fixture-directory cleanup after proving the process cleanup
# trap is disarmed. The fake QEMU must remain alive until explicit cleanup.
trap 'rm -rf -- "$work"' EXIT
assert_running "$persistent_pidfile" || {
  printf 'persistent fake QEMU did not survive disarmed cleanup\n' >&2
  exit 1
}
nas_qemu_cleanup_pidfile "$persistent_pidfile" 1
[[ ! -e "$persistent_pidfile" ]] || {
  printf 'persistent pidfile survived explicit cleanup\n' >&2
  exit 1
}

exec {fake_qemu_hold_fd}>&-
printf '%s\n' "Persistent QEMU lifecycle contract passed"
