#!/usr/bin/env bash

# Small, dependency-free cleanup stack for VM test wrappers.  The owner installs
# one EXIT trap; individual phases only register handlers with this stack.

declare -ag NAS_VM_CLEANUP_HANDLERS=()

nas_vm_cleanup_add() {
  local handler=${1:-}
  [[ "$handler" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || {
    printf 'nas-vm-cleanup: invalid handler: %s\n' "$handler" >&2
    return 2
  }
  NAS_VM_CLEANUP_HANDLERS+=("$handler")
}

nas_vm_cleanup_run() {
  local original_status=${1:-$?}
  local cleanup_status=0 handler index
  for ((index = ${#NAS_VM_CLEANUP_HANDLERS[@]} - 1; index >= 0; index--)); do
    handler=${NAS_VM_CLEANUP_HANDLERS[index]}
    if "$handler" "$original_status"; then
      :
    else
      cleanup_status=$?
      printf 'nas-vm-cleanup: handler %s failed with status %s\n' "$handler" "$cleanup_status" >&2
    fi
  done
  if ((original_status != 0)); then
    return "$original_status"
  fi
  return "$cleanup_status"
}

nas_vm_cleanup_trap() {
  local status=$?
  nas_vm_cleanup_run "$status"
}
