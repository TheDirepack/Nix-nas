#!/usr/bin/env bash

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
  if kill -0 "$pid" 2>/dev/null; then
    # QEMU is daemonized by qemu-system-x86_64, so it is not a child of this
    # shell and wait(2) cannot reap it. Only escalate to KILL if it is still
    # alive after the grace period, then poll until it is gone.
    kill -KILL "$pid" 2>/dev/null || true
    for _ in $(seq 1 "$grace_seconds"); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
  fi
  rm -f -- "$pidfile"
}

nas_qemu_cleanup_pidfile() {
  local pidfile=$1 grace_seconds=${2:-20}
  nas_qemu_stop_pidfile "$pidfile" "$grace_seconds"
}

nas_qemu_disarm_cleanup() {
  trap - EXIT INT TERM
}
