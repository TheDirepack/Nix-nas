#!/usr/bin/env bash
# Cleanup handlers are registered by name and invoked indirectly by the EXIT trap.
# shellcheck disable=SC2317
set -Eeuo pipefail

# Exercise the same cleanup and profiling libraries embedded in the NixOS VM
# wrappers. This is deliberately process-level: each case exits or receives a
# signal only after it has created every run-owned resource.
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nas-vm-cleanup-contract.XXXXXX")"

cleanup_work() {
  rm -rf -- "$WORK"
}
trap cleanup_work EXIT

# shellcheck disable=SC1091
source "$ROOT/scripts/lib/nas-vm-cleanup.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/nas-vm-js-deps.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/nas-vm-profile.sh"
# shellcheck disable=SC1091
source "$ROOT/tests/vm/timeout-budget.sh"

run_case() {
  local label=$1 mode=$2 case_dir="$WORK/${3:-case}"
  mkdir -p "$case_dir"
  (
    set -Eeuo pipefail
    printf '%s\n' "$BASHPID" >"$case_dir/runner.pid"
    # shellcheck disable=SC1091
    source "$ROOT/scripts/lib/nas-vm-cleanup.sh"
    # shellcheck disable=SC1091
    source "$ROOT/scripts/lib/nas-vm-js-deps.sh"
    # shellcheck disable=SC1091
    source "$ROOT/scripts/lib/nas-vm-profile.sh"
    # shellcheck disable=SC1091
    source "$ROOT/tests/vm/timeout-budget.sh"

    export NAS_VM_TIMEOUT_BUDGET_FILE="$ROOT/tests/vm/timeout-budget.json"
    export NAS_VM_PROFILE_OUTPUT="$case_dir/profile.log"
    # shellcheck disable=SC2030
    export NAS_VM_CLEANUP_OUTPUT="$case_dir/cleanup.log"
    export NAS_VM_ARTIFACT_PATH="$case_dir/evidence/profile.json"
    mkdir -p "$case_dir/evidence" "$case_dir/repo/tests/js-fuzz" "$case_dir/fast-check"
    printf 'secret material\n' >"$case_dir/secrets"
    mkdir -p "$case_dir/state"

    # shellcheck disable=SC2329
    cleanup_outpost() {
      local status=${1:-0} pid
      if [[ -s "$case_dir/outpost.pid" ]]; then
        pid="$(<"$case_dir/outpost.pid")"
        printf '%s\n' "$pid" >"$case_dir/outpost.pid.observed"
        kill "$pid" 2>/dev/null || true
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
      fi
      rm -f -- "$case_dir/outpost.pid"
      : >"$case_dir/outpost.cleaned"
      return 0
    }
    # shellcheck disable=SC2329
    cleanup_secret() {
      rm -rf -- "$case_dir/secrets"
      : >"$case_dir/secrets.cleaned"
      return 0
    }
    # shellcheck disable=SC2329
    cleanup_state() {
      rm -rf -- "$case_dir/state"
      : >"$case_dir/state.cleaned"
      return 0
    }
    # shellcheck disable=SC2329
    cleanup_dependencies() {
      nas_vm_js_deps_cleanup 0
    }
    workload_pid=""
    # shellcheck disable=SC2329
    cleanup_stage_workload() {
      if [[ -n "$workload_pid" ]]; then
        printf '%s\n' "$workload_pid" >"$case_dir/workload.pid.observed"
        kill "$workload_pid" 2>/dev/null || true
        kill -KILL "$workload_pid" 2>/dev/null || true
        wait "$workload_pid" 2>/dev/null || true
      fi
      workload_pid=""
      return 0
    }

    nas_vm_profile_install
    nas_vm_cleanup_add cleanup_outpost
    nas_vm_cleanup_add cleanup_secret
    nas_vm_cleanup_add cleanup_state
    nas_vm_cleanup_add cleanup_dependencies
    nas_vm_cleanup_add cleanup_stage_workload

    (exec -a authentik-outpost-contract-sim sleep 600) &
    printf '%s\n' "$!" >"$case_dir/outpost.pid"

    if [[ $label == "Run the complete first-time setup CLI" ]]; then
      NAS_FULL_SUITE_TEST_FAILURE=after-js-deps-directory \
        nas_vm_js_deps_prepare "$case_dir/repo" "$case_dir/fast-check" || {
          prepare_status=$?
          [[ $prepare_status -eq 97 ]] || exit "$prepare_status"
        }
    else
      nas_vm_js_deps_prepare "$case_dir/repo" "$case_dir/fast-check"
    fi

    nas_vm_profile_command "log \"$label\""
    # shellcheck disable=SC2034
    NAS_VM_LAST_COMMAND="injected-$mode $label"
    trap - DEBUG
    trap 'exit 143' INT TERM
    if [[ $mode == cancel ]]; then
      (exec -a "nas-vm-${label//[^a-zA-Z0-9]/-}" sleep 600) &
      workload_pid=$!
      # Self-deliver the same signal a CI cancellation sends to the runner.
      # Doing it in the child process keeps this contract test independent of
      # the host process group and still exercises the real EXIT trap.
      kill -TERM "$BASHPID"
      sleep 600
    else
      exit 73
    fi
  )
}

while IFS= read -r label; do
  [[ -n "$label" ]] || continue
  case_name="failure-${RANDOM}-${RANDOM}"
  if run_case "$label" fail "$case_name"; then
    printf 'cleanup contract: failure injection unexpectedly passed: %s\n' "$label" >&2
    exit 1
  else
    status=$?
  fi
  [[ $status -eq 73 ]] || {
    printf 'cleanup contract: wrong failure status for %s: %s\n' "$label" "$status" >&2
    exit 1
  }
  case_dir="$WORK/$case_name"
  grep -Fq "VM-PHASE-START: $label" "$case_dir/profile.log"
  grep -Fq "VM-PHASE-TIMING: $label:" "$case_dir/profile.log"
  grep -Fq "VM-PHASE-BUDGET:" "$case_dir/profile.log"
  grep -Fq 'VM-LAST-COMMAND: injected-fail' "$case_dir/profile.log"
  grep -Fq "VM-ARTIFACT-PATH: $case_dir/evidence/profile.json" "$case_dir/profile.log"
  grep -Fq 'VM-CLEANUP-STATUS: 0' "$case_dir/cleanup.log"
  test -f "$case_dir/outpost.cleaned"
  test -f "$case_dir/secrets.cleaned"
  test -f "$case_dir/state.cleaned"
  test ! -e "$case_dir/secrets"
  test ! -e "$case_dir/state"
  test ! -e "$case_dir/repo/tests/js-fuzz/node_modules"
  test ! -e "$case_dir/outpost.pid"

  cancel_name="cancel-${RANDOM}-${RANDOM}"
  if run_case "$label" cancel "$cancel_name"; then
    printf 'cleanup contract: cancellation unexpectedly passed: %s\n' "$label" >&2
    exit 1
  else
    status=$?
  fi
  [[ $status -eq 143 ]] || {
    printf 'cleanup contract: wrong cancellation status for %s: %s\n' "$label" "$status" >&2
    exit 1
  }
  case_dir="$WORK/$cancel_name"
  grep -Fq 'VM-CLEANUP-STATUS: 0' "$case_dir/cleanup.log"
  test ! -e "$case_dir/secrets"
  test ! -e "$case_dir/state"
  test ! -e "$case_dir/repo/tests/js-fuzz/node_modules"
  test ! -e "$case_dir/outpost.pid"
  test -f "$case_dir/workload.pid.observed"
  kill -0 "$(<"$case_dir/workload.pid.observed")" 2>/dev/null && exit 1
  kill -0 "$(<"$case_dir/outpost.pid.observed")" 2>/dev/null && exit 1

  # The second invocation reuses the exact paths after cancellation. A stale
  # process, secret, symlink, or dependency directory makes this fail before
  # the test body can start.
  rerun_name="rerun-${RANDOM}-${RANDOM}"
  run_case "$label" fail "$rerun_name" || rerun_status=$?
  [[ ${rerun_status:-0} -eq 73 ]] || {
    printf 'cleanup contract: rerun did not reach its injected failure: %s\n' "$label" >&2
    exit 1
  }
  unset rerun_status
done < <(jq -er '.phases[].label' "$ROOT/tests/vm/timeout-budget.json")

for stage in package-install secret-activation browser-tests fuzzing artifact-upload; do
  stage_name="cancel-stage-${stage//[^a-zA-Z0-9]/-}"
  if run_case "$stage" cancel "$stage_name"; then
    printf 'cleanup contract: cancellation unexpectedly passed: %s\n' "$stage" >&2
    exit 1
  else
    status=$?
  fi
  [[ $status -eq 143 ]] || exit 1
  case_dir="$WORK/$stage_name"
  grep -Fq "VM-PHASE-START: $stage" "$case_dir/profile.log"
  grep -Fq "VM-PHASE-TIMING: $stage:" "$case_dir/profile.log"
  grep -Fq 'VM-CLEANUP-STATUS: 0' "$case_dir/cleanup.log"
  test ! -e "$case_dir/secrets"
  test ! -e "$case_dir/state"
  test ! -e "$case_dir/repo/tests/js-fuzz/node_modules"
  test ! -e "$case_dir/outpost.pid"
  test -f "$case_dir/workload.pid.observed"
  kill -0 "$(<"$case_dir/workload.pid.observed")" 2>/dev/null && exit 1
  kill -0 "$(<"$case_dir/outpost.pid.observed")" 2>/dev/null && exit 1
done

cleanup_failure_dir="$WORK/cleanup-failure"
if (
  set -Eeuo pipefail
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib/nas-vm-cleanup.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib/nas-vm-js-deps.sh"
  mkdir -p "$cleanup_failure_dir/node_modules"
  NAS_VM_JS_DEPS_PATH="$cleanup_failure_dir/node_modules"
  NAS_VM_JS_DEPS_OWNED=1
  # shellcheck disable=SC2329
  nas_vm_js_deps_remove() { return 91; }
  nas_vm_cleanup_add nas_vm_js_deps_cleanup
  trap nas_vm_cleanup_trap EXIT
  exit 0
); then
  printf 'cleanup contract: dependency removal failure unexpectedly passed\n' >&2
  exit 1
else
  status=$?
fi
[[ $status -eq 91 ]] || {
  printf 'cleanup contract: dependency removal failure returned %s, expected 91\n' "$status" >&2
  exit 1
}

printf 'VM cleanup/profile failure-injection contract passed\n'
