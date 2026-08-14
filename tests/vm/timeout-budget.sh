#!/usr/bin/env bash

nas_vm_timeout_manifest_path() {
  printf '%s\n' "${NAS_VM_TIMEOUT_BUDGET_FILE:-${CONFIG_DIR:-/var/lib/nas-test/repo}/tests/vm/timeout-budget.json}"
}

nas_vm_timeout_value() {
  local key=$1
  jq -er --arg key "$key" '.timeouts[$key] | numbers' "$(nas_vm_timeout_manifest_path)"
}

nas_vm_outer_value() {
  local key=$1
  jq -er --arg key "$key" '.outer[$key] | numbers' "$(nas_vm_timeout_manifest_path)"
}

nas_vm_kill_after_seconds() {
  nas_vm_timeout_value killAfter
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

nas_vm_integration_timeout_seconds() {
  local guest
  guest=$(nas_vm_guest_watchdog_seconds)
  printf '%s\n' "$((guest + $(nas_vm_timeout_value secretAdversarial) + $(nas_vm_timeout_value installedSmoke) + $(nas_vm_outer_value nativeBoot) + $(nas_vm_outer_value nativeShutdown) + $(nas_vm_outer_value slack)))"
}

nas_vm_encrypted_timeout_seconds() {
  printf '%s\n' "$(( $(nas_vm_timeout_value encryptedGuest) + $(nas_vm_outer_value nativeBoot) + $(nas_vm_outer_value nativeShutdown) + $(nas_vm_outer_value slack) ))"
}

nas_vm_installer_timeout_seconds() {
  local guest
  guest=$(nas_vm_guest_watchdog_seconds)
  printf '%s\n' "$((guest + $(nas_vm_timeout_value reconfigure) + $(nas_vm_outer_value installerSetup) + $(nas_vm_outer_value installerBoot) + $(nas_vm_outer_value installerReboot) + $(nas_vm_outer_value nativeShutdown) + $(nas_vm_outer_value slack)))"
}

nas_vm_full_suite_timeout_seconds() {
  printf '%s\n' "$(( $(nas_vm_outer_value fullSuiteSetup) + $(nas_vm_integration_timeout_seconds) ))"
}

nas_vm_ci_integration_timeout_seconds() {
  printf '%s\n' "$(( $(nas_vm_integration_timeout_seconds) + $(nas_vm_outer_value ciSetup) ))"
}

nas_vm_ci_installer_timeout_seconds() {
  printf '%s\n' "$(( $(nas_vm_installer_timeout_seconds) + $(nas_vm_outer_value ciSetup) ))"
}
