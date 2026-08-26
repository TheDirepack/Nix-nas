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
  # Model the detached persistent VM rather than a shell-owned background job.
  # nohup preserves the real executable PID while making it independent of the
  # launching subshell. Wait for the asynchronous child to complete exec before
  # exposing its pidfile, otherwise cleanup can race /proc/<pid>/exe and reject
  # a still-bash process as not being qemu-system-x86_64.
  local pid
  nohup "$fake_qemu" 60 </dev/null >/dev/null 2>&1 &
  pid=$!
  if ! wait_for_fake_qemu_exec "$pid"; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
  fi
  printf '%s\n' "$pid" > "$1"
  if (($# > 1)); then
    printf '%s\n' "$pid" > "$2"
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
[[ "$failure_status" -eq 97 ]] || {
  printf 'failure-path fixture returned %s instead of 97\n' "$failure_status" >&2
  exit 1
}
if kill -0 "$(<"$work/failure.process")" 2>/dev/null; then
  printf 'failure-path fake QEMU survived armed cleanup\n' >&2
  exit 1
fi
[[ ! -e "$failure_pidfile" ]] || {
  printf 'failure-path pidfile survived armed cleanup\n' >&2
  exit 1
}

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
assert_running "$persistent_pidfile" || {
  printf 'persistent fake QEMU did not survive disarmed cleanup\n' >&2
  exit 1
}
nas_qemu_cleanup_pidfile "$persistent_pidfile" 1
[[ ! -e "$persistent_pidfile" ]] || {
  printf 'persistent pidfile survived explicit cleanup\n' >&2
  exit 1
}

printf '%s\n' "Persistent QEMU lifecycle contract passed"
