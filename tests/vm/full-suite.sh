#!/usr/bin/env bash
set -Eeuo pipefail

repo="${NAS_FULL_SUITE_REPO:-/var/lib/nas-test/repo}"
[[ -d "$repo" ]] || {
  printf 'full VM suite: repository is missing: %s\n' "$repo" >&2
  exit 1
}
cd -- "$repo"

# This helper owns the run-created node_modules tree even when dependency
# installation fails halfway through. A failed run must not poison its rerun.
# shellcheck disable=SC1091
source "$repo/scripts/lib/nas-vm-js-deps.sh"
# shellcheck disable=SC1091
source "$repo/scripts/lib/nas-vm-cleanup.sh"
# shellcheck disable=SC1091
source "$repo/tests/vm/timeout-budget.sh"
export NAS_VM_TIMEOUT_BUDGET_FILE="$repo/tests/vm/timeout-budget.json"

work="$(mktemp -d "${TMPDIR:-/tmp}/nas-full-suite.XXXXXX")"

cleanup_work() {
  rm -rf -- "$work"
}

nas_vm_cleanup_add cleanup_work
nas_vm_cleanup_add nas_vm_js_deps_cleanup
trap nas_vm_cleanup_trap EXIT
mkdir -p "$work/"{home,tmp,secrets/ai,llama-swap}
printf 'models: {}\npeers: {}\nselectors: {}\n' >"$work/llama-swap/config.yaml"
touch "$work/secrets/ready"

# Keep source tests hermetic even though this process runs as root in a real
# appliance VM. The appliance checks below intentionally use the VM's real
# /run, /var/lib, systemd, and ZFS state instead.
export HOME="$work/home"
export TMPDIR="$work/tmp"
export NAS_CONFIG_DIR="$repo"
export NAS_STATE_ALLOW_UNPRIVILEGED=1
export NAS_STATE_RUNTIME_ROOT="$work/state"
export NAS_STATE_ROLLBACK_ROOT="$work/rollback"
export NAS_STATE_RESTORE_JOURNAL="$work/rollback/restore-operation.json"
export NAS_SECRET_ROOT="$work/secrets"
export NAS_LLAMA_SWAP_CONFIG="$work/llama-swap/config.yaml"
export NAS_V2_DESIRED="$work/control/services"
export NAS_V2_EFFECTIVE="$work/control/effective.json"
export NAS_V2_SCHEMA="$repo/schemas/managed-services-v3.schema.json"
export NAS_SETUP_STATE="$work/setup/state.json"
export NAS_SETUP_JOURNAL="$work/setup/first-run-journal.json"
export NAS_SETUP_STATE_ROOT="$work/setup"
export NAS_OPERATION_ROOT="$work/operations"
export NAS_OPERATION_GROUP=users
export NAS_IDENTITY_LOCK="$work/identity.lock"
export NAS_COCKPIT_SUPERUSER_BYPASS=1
export NAS_PREFLIGHT_STATUS_FILE="$work/preflight.json"

mkdir -p \
  "$NAS_STATE_RUNTIME_ROOT" "$NAS_STATE_ROLLBACK_ROOT" "$work/control/services" \
  "$NAS_SETUP_STATE_ROOT" "$NAS_OPERATION_ROOT"
printf 'schemaVersion: 3\nservices: {}\n' >"$NAS_V2_DESIRED/00-default.yaml"
printf '{}\n' >"$NAS_V2_EFFECTIVE"
printf '{}\n' >"$NAS_SETUP_STATE"

run_appliance() {
  env \
    -u HOME \
    -u TMPDIR \
    -u NAS_CONFIG_DIR \
    -u NAS_STATE_ALLOW_UNPRIVILEGED \
    -u NAS_STATE_RUNTIME_ROOT \
    -u NAS_STATE_ROLLBACK_ROOT \
    -u NAS_STATE_RESTORE_JOURNAL \
    -u NAS_SECRET_ROOT \
    -u NAS_LLAMA_SWAP_CONFIG \
    -u NAS_V2_DESIRED \
    -u NAS_V2_EFFECTIVE \
    -u NAS_V2_SCHEMA \
    -u NAS_SETUP_STATE \
    -u NAS_SETUP_JOURNAL \
    -u NAS_SETUP_STATE_ROOT \
    -u NAS_OPERATION_ROOT \
    -u NAS_OPERATION_GROUP \
    -u NAS_IDENTITY_LOCK \
    -u NAS_COCKPIT_SUPERUSER_BYPASS \
    -u NAS_PREFLIGHT_STATUS_FILE \
    "$@"
}

printf '\n==> Complete source preflight and unit suite\n'
NAS_PREFLIGHT_REQUIRE_COMPLETE=1 ./scripts/preflight.sh

if [[ "${NAS_FULL_SUITE_SKIP_FUZZ:-0}" == "1" ]]; then
  printf '\n==> Property, fuzz, executable-contract, and JavaScript suite (deferred)\n'
else
  if [[ -n "${NAS_FAST_CHECK_PATH:-}" ]]; then
    # The native NixOS test can provide the exact pinned fast-check package as a
    # store path. Keep the generated dependency link out of structure validation.
    nas_vm_js_deps_prepare "$repo" "$NAS_FAST_CHECK_PATH"
  else
    printf '\n==> Installing the lockfile-pinned JavaScript fuzz dependency in the VM\n'
    nas_vm_js_deps_prepare "$repo"
  fi

  printf '\n==> Property, fuzz, executable-contract, and JavaScript suite\n'
  ./scripts/run-fuzz.py
fi

printf '\n==> Deterministic security tier\n'
./scripts/run-security-tests.py

printf '\n==> Nix configuration and negative-fixture suite\n'
./scripts/nix-config-matrix.sh

printf '\n==> Full-stack appliance suite\n'
run_appliance timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
  "${NAS_VM_FULL_SUITE_GUEST_TIMEOUT:-$(nas_vm_guest_watchdog_seconds)}" nas-vm-guest-test /dev/vdb
run_appliance timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
  "${NAS_VM_FULL_SUITE_SECRET_TIMEOUT:-$(nas_vm_timeout_value secretAdversarial)}" nas-vm-secret-adversarial
NAS_INSTALLED_FUZZ_SMOKE=1 \
  run_appliance timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "${NAS_VM_FULL_SUITE_INSTALLED_TIMEOUT:-$(nas_vm_timeout_value installedSmoke)}" \
    python3 tests/vm/adversarial-installed.py >"$work/nas-installed-command-smoke.json"
jq -e '.ok == true and .smoke == true and .commands > 0' \
  "$work/nas-installed-command-smoke.json" >/dev/null

printf '\nFULL NIXOS NAS VM SUITE PASSED\n'
