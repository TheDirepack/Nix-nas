#!/usr/bin/env bash

nas_vm_timeout_manifest_path() {
  printf '%s\n' "${NAS_VM_TIMEOUT_BUDGET_FILE:-${CONFIG_DIR:-/var/lib/nas-test/repo}/tests/vm/timeout-budget.json}"
}

nas_vm_timeout_value() {
  local key=$1
  jq -er --arg key "$key" '.timeouts[$key] | numbers' "$(nas_vm_timeout_manifest_path)"
}

nas_vm_ordinary_wait_seconds() {
  jq -er '.ordinaryWaitSeconds | numbers' "$(nas_vm_timeout_manifest_path)"
}

nas_vm_phase_metadata() {
  local label=$1
  jq -er --arg label "$label" '
    . as $manifest
    | $manifest.phases[]
    | select(.label == $label)
    | [
        .id,
        (.fixedSeconds
          + (.ordinaryWaits * $manifest.ordinaryWaitSeconds)
          + ([.timeoutKeys[] | $manifest.timeouts[.]] | add // 0))
      ]
    | @tsv
  ' "$(nas_vm_timeout_manifest_path)"
}

nas_vm_guest_watchdog_seconds() {
  jq -er '
    . as $manifest
    | (
        [
          $manifest.phases[]
          | (.fixedSeconds
            + (.ordinaryWaits * $manifest.ordinaryWaitSeconds)
            + ([.timeoutKeys[] | $manifest.timeouts[.]] | add // 0))
        ]
        | add
      ) + $manifest.slackSeconds
  ' "$(nas_vm_timeout_manifest_path)"
}
