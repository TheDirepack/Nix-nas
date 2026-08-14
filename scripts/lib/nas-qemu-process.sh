#!/usr/bin/env bash

nas_qemu_pid_from_pidfile() {
  local pidfile=$1 pid executable
  QEMU_PID=""
  [[ -s "$pidfile" ]] || return 1
  pid="$(<"$pidfile")"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  executable="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  [[ "${executable##*/}" == qemu-system-x86_64 ]] || {
    printf 'error: refusing to signal pid %s from %s because it is not qemu-system-x86_64\n' "$pid" "$pidfile" >&2
    return 2
  }
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
