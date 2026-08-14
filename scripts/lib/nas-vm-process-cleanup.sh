#!/usr/bin/env bash

nas_vm_stop_process() {
  local pid=${1:-} grace_seconds=${2:-30}
  [[ "$pid" =~ ^[0-9]+$ ]] || return 2
  [[ "$grace_seconds" =~ ^[0-9]+$ ]] || return 2
  kill -0 "$pid" >/dev/null 2>&1 || return 0

  kill -TERM "$pid" >/dev/null 2>&1 || true
  # shellcheck disable=SC2016
  if ! timeout --foreground --signal=TERM --kill-after=5s "${grace_seconds}s" \
    bash -c 'while kill -0 "$1" >/dev/null 2>&1; do sleep 1; done' \
    nas-vm-stop-process "$pid"; then
    kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
  wait "$pid" >/dev/null 2>&1 || true
  ! kill -0 "$pid" >/dev/null 2>&1
}
