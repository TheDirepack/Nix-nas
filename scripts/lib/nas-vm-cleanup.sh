#!/usr/bin/env bash

# Small, dependency-free cleanup stack for VM test wrappers.  The owner installs
# one EXIT trap; individual phases only register handlers with this stack.

declare -ag NAS_VM_CLEANUP_HANDLERS=()
declare -ag NAS_VM_CLEANUP_FAILED_HANDLERS=()

nas_vm_cleanup_emit() {
  if [[ -n "${NAS_VM_CLEANUP_OUTPUT:-}" ]]; then
    printf '%s\n' "$*" >>"$NAS_VM_CLEANUP_OUTPUT"
  else
    printf '%s\n' "$*" >&2
  fi
}

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
  NAS_VM_CLEANUP_FAILED_HANDLERS=()
  for ((index = ${#NAS_VM_CLEANUP_HANDLERS[@]} - 1; index >= 0; index--)); do
    handler=${NAS_VM_CLEANUP_HANDLERS[index]}
    if "$handler" "$original_status"; then
      :
    else
      cleanup_status=$?
      NAS_VM_CLEANUP_FAILED_HANDLERS+=("$handler")
      nas_vm_cleanup_emit "VM-CLEANUP-HANDLER-FAILURE: $handler=$cleanup_status"
    fi
  done
  nas_vm_cleanup_emit "VM-CLEANUP-STATUS: $cleanup_status"
  if ((${#NAS_VM_CLEANUP_FAILED_HANDLERS[@]} > 0)); then
    nas_vm_cleanup_emit "VM-CLEANUP-FAILED-HANDLERS: ${NAS_VM_CLEANUP_FAILED_HANDLERS[*]}"
  fi
  if ((original_status != 0)); then
    return "$original_status"
  fi
  return "$cleanup_status"
}

nas_vm_cleanup_trap() {
  local status=$?
  # A profiler may own DEBUG while the process is running. Disable it before
  # the cleanup stack starts so cleanup bookkeeping cannot replace the failed
  # command in the final observability record.
  trap - DEBUG
  nas_vm_cleanup_run "$status"
}
