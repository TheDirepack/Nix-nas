#!/usr/bin/env bash

# Guest-side phase profiler. The NixOS wrapper and executable tests both use
# this file so cleanup and observability cannot drift between them.

NAS_VM_PHASE_STARTED=${NAS_VM_PHASE_STARTED:-$SECONDS}
NAS_VM_PHASE_NAME=${NAS_VM_PHASE_NAME:-}
NAS_VM_FIRST_RUN_TIMER_PID=${NAS_VM_FIRST_RUN_TIMER_PID:-}
NAS_VM_LAST_COMMAND=${NAS_VM_LAST_COMMAND:-}

nas_vm_profile_emit() {
  if [[ -n "${NAS_VM_PROFILE_OUTPUT:-}" ]]; then
    printf '%s\n' "$*" >>"$NAS_VM_PROFILE_OUTPUT"
  else
    printf '%s\n' "$*"
  fi
}

nas_vm_stop_first_run_timer() {
  if [[ -n "$NAS_VM_FIRST_RUN_TIMER_PID" ]]; then
    kill "$NAS_VM_FIRST_RUN_TIMER_PID" >/dev/null 2>&1 || true
    wait "$NAS_VM_FIRST_RUN_TIMER_PID" 2>/dev/null || true
    NAS_VM_FIRST_RUN_TIMER_PID=""
  fi
}

nas_vm_start_first_run_timer() {
  nas_vm_stop_first_run_timer
  (
    local started=$SECONDS
    while sleep 60; do
      nas_vm_profile_emit "VM-FIRST-RUN-TIMING: $((SECONDS - started))s elapsed"
    done
  ) &
  NAS_VM_FIRST_RUN_TIMER_PID=$!
}

nas_vm_profile_command() {
  local command=${1:-} now phase_name
  case "$command" in
    exit\ * | trap\ * | nas_vm_cleanup* | nas_vm_profile_cleanup*) ;;
    *) NAS_VM_LAST_COMMAND=$command ;;
  esac
  case "$command" in
    log\ *)
      nas_vm_stop_first_run_timer
      now=$SECONDS
      if [[ -n "$NAS_VM_PHASE_NAME" ]]; then
        nas_vm_profile_emit "VM-PHASE-TIMING: $NAS_VM_PHASE_NAME: $((now - NAS_VM_PHASE_STARTED))s (complete)"
      fi
      phase_name="${command#log }"
      phase_name="${phase_name#\"}"
      phase_name="${phase_name%\"}"
      NAS_VM_PHASE_NAME=$phase_name
      NAS_VM_PHASE_STARTED=$now
      nas_vm_profile_emit "VM-PHASE-START: $NAS_VM_PHASE_NAME"
      ;;
    python3*first-run-wizard.py*)
      nas_vm_profile_emit "VM-FIRST-RUN-START: $NAS_VM_PHASE_NAME"
      nas_vm_start_first_run_timer
      ;;
    jq\ -e*)
      nas_vm_stop_first_run_timer
      ;;
  esac
}

nas_vm_profile_cleanup() {
  local rc=${1:-0} now=$SECONDS metadata phase_id phase_budget
  trap - DEBUG
  nas_vm_stop_first_run_timer
  if [[ -n "$NAS_VM_PHASE_NAME" ]]; then
    metadata="$(nas_vm_phase_metadata "$NAS_VM_PHASE_NAME" 2>/dev/null || true)"
    if [[ -n "$metadata" ]]; then
      IFS=$'\t' read -r phase_id phase_budget <<<"$metadata"
      nas_vm_profile_emit "VM-PHASE-BUDGET: $phase_id: ${phase_budget}s"
    fi
    if [[ $rc -eq 0 ]]; then
      nas_vm_profile_emit "VM-PHASE-TIMING: $NAS_VM_PHASE_NAME: $((now - NAS_VM_PHASE_STARTED))s (complete)"
    else
      nas_vm_profile_emit "VM-PHASE-TIMING: $NAS_VM_PHASE_NAME: $((now - NAS_VM_PHASE_STARTED))s (failed)" >&2
    fi
  fi
  nas_vm_profile_emit "VM-LAST-COMMAND: ${NAS_VM_LAST_COMMAND:-unknown}"
  if [[ -n "${NAS_VM_ARTIFACT_PATH:-}" ]]; then
    nas_vm_profile_emit "VM-ARTIFACT-PATH: $NAS_VM_ARTIFACT_PATH"
  fi
  # The cleanup stack preserves the original test status. A handler must
  # report only its own cleanup result or a failed test looks like cleanup
  # failure even when every owned resource was removed.
  return 0
}

nas_vm_profile_install() {
  trap 'nas_vm_profile_command "$BASH_COMMAND"' DEBUG
  nas_vm_cleanup_add nas_vm_profile_cleanup
  trap nas_vm_cleanup_trap EXIT
}
