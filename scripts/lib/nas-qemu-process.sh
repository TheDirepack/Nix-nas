#!/usr/bin/env bash

# Lock file must live outside the disposable CACHE_DIR; deleting or
# recreating that directory must never split mutual exclusion across inodes.
# This caller-scoped descriptor remains held until its shell exits.
nas_qemu_acquire_shared_state_lock() {
  local lock_path=$1
  command -v flock >/dev/null 2>&1 || {
    printf 'error: flock is required for shared QEMU state ownership\n' >&2
    return 1
  }
  exec {NAS_QEMU_SHARED_LOCK_FD}> "$lock_path" || return 1
  if ! flock -n -x "$NAS_QEMU_SHARED_LOCK_FD"; then
    exec {NAS_QEMU_SHARED_LOCK_FD}>&-
    printf 'error: shared QEMU state is already owned by another operation: %s\n' "$lock_path" >&2
    return 1
  fi
}

nas_qemu_pid_from_pidfile() {
  local pidfile=$1 pid executable
  QEMU_PID=""
  [[ -s "$pidfile" ]] || return 1
  pid="$(<"$pidfile")"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  executable="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  executable="${executable% (deleted)}"
  case "${executable##*/}" in
    qemu-system-x86_64|.qemu-system-x86_64-wrapped) ;;
    *)
      printf 'error: refusing to signal pid %s from %s because it is not qemu-system-x86_64\n' "$pid" "$pidfile" >&2
      return 2
      ;;
  esac
  QEMU_PID="$pid"
}

nas_qemu_stop_pidfile() {
  local pidfile=$1 grace_seconds=${2:-20} pid
  if nas_qemu_pid_from_pidfile "$pidfile"; then
    pid="$QEMU_PID"
  else
    local status=$?
    (( status == 2 )) && return 2
    rm -f -- "$pidfile"
    return 0
  fi

  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 "$grace_seconds"); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f -- "$pidfile"
}

nas_qemu_cleanup_pidfile() {
  local pidfile=$1 grace_seconds=${2:-20}
  nas_qemu_stop_pidfile "$pidfile" "$grace_seconds"
}

nas_qemu_disarm_cleanup() {
  trap - EXIT INT TERM
}

# Refuse to reuse or replace a disk owned by a running, separately managed VM.
# Exit 1: legitimate QEMU conflicts with this operation. Exit 2: PID belongs
# to a different process (never trust it as permission to delete any disks).
# Exit 0: no running owner, or an intentionally reused complete persistent VM.
nas_qemu_guard_shared_installer_state() {
  local pidfile=$1 persistent_mode=$2 reuse_installed=$3 os_disk=$4 data_disk=$5 ssh_key=$6 install_marker=$7
  local status
  [[ -s "$pidfile" ]] || return 0
  if nas_qemu_pid_from_pidfile "$pidfile"; then
    if [[ "$persistent_mode" != 1 ]]; then
      printf 'error: installer cannot use shared QEMU disks while a persistent VM is running: %s\n' "$pidfile" >&2
      return 1
    fi
    if [[ "$reuse_installed" != 1 || ! -s "$os_disk" || ! -s "$data_disk" || ! -s "$ssh_key" || ! -s "$install_marker" ]]; then
      printf 'error: active persistent VM has incomplete or non-reusable state; stop it before reinstalling: %s\n' "$pidfile" >&2
      return 1
    fi
    return 0
  else
    status=$?
    if (( status == 2 )); then
      printf 'error: refusing installer state with foreign PID owner: %s\n' "$pidfile" >&2
      return 2
    fi
  fi
  return 0
}
