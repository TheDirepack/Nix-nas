#!/usr/bin/env bash
set -Eeuo pipefail

repo="${NAS_FULL_SUITE_REPO:-/var/lib/nas-test/repo}"
[[ -d "$repo" ]] || {
  printf 'full VM suite: repository is missing: %s\n' "$repo" >&2
  exit 1
}
cd -- "$repo"

work="$(mktemp -d "${TMPDIR:-/tmp}/nas-full-suite.XXXXXX")"
js_node_modules_created=0

cleanup() {
  if (( js_node_modules_created == 1 )); then
    rm -rf -- "$repo/tests/js-fuzz/node_modules"
  fi
  rm -rf -- "$work"
}

trap cleanup EXIT
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
export NAS_FEATURE_STATE="$work/control/settings.json"
export NAS_FEATURE_JOURNAL="$work/control/transaction.json"
export NAS_FEATURE_LAST_GOOD="$work/control/settings.last-good.json"
export NAS_FEATURE_RUNTIME="$work/control/on-demand.json"
export NAS_FEATURE_LOCK="$work/control/feature-control.lock"
export NAS_FEATURE_CATALOG="$work/control/features.json"
export NAS_FEATURE_STATE_ROOT="$work/control"
export NAS_SETUP_STATE="$work/setup/state.json"
export NAS_SETUP_JOURNAL="$work/setup/first-run-journal.json"
export NAS_SETUP_STATE_ROOT="$work/setup"
export NAS_OPERATION_ROOT="$work/operations"
export NAS_OPERATION_GROUP=users
export NAS_IDENTITY_LOCK="$work/identity.lock"
export NAS_COCKPIT_SUPERUSER_BYPASS=1
export NAS_PREFLIGHT_STATUS_FILE="$work/preflight.json"

mkdir -p \
  "$NAS_STATE_RUNTIME_ROOT" "$NAS_STATE_ROLLBACK_ROOT" "$NAS_FEATURE_STATE_ROOT" \
  "$NAS_SETUP_STATE_ROOT" "$NAS_OPERATION_ROOT"
printf '{}\n' >"$NAS_FEATURE_CATALOG"
printf '{}\n' >"$NAS_FEATURE_STATE"
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
    -u NAS_FEATURE_STATE \
    -u NAS_FEATURE_JOURNAL \
    -u NAS_FEATURE_LAST_GOOD \
    -u NAS_FEATURE_RUNTIME \
    -u NAS_FEATURE_LOCK \
    -u NAS_FEATURE_CATALOG \
    -u NAS_FEATURE_STATE_ROOT \
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
    if [[ -e tests/js-fuzz/node_modules ]]; then
      printf 'full VM suite: tests/js-fuzz/node_modules already exists\n' >&2
      exit 1
    fi
    mkdir -p tests/js-fuzz/node_modules
    js_node_modules_created=1
    ln -s -- "$NAS_FAST_CHECK_PATH" tests/js-fuzz/node_modules/fast-check
  else
    printf '\n==> Installing the lockfile-pinned JavaScript fuzz dependency in the VM\n'
    if [[ -e tests/js-fuzz/node_modules ]]; then
      printf 'full VM suite: tests/js-fuzz/node_modules already exists\n' >&2
      exit 1
    fi
    npm --prefix tests/js-fuzz ci --no-audit --no-fund
    js_node_modules_created=1
  fi

  printf '\n==> Property, fuzz, executable-contract, and JavaScript suite\n'
  ./scripts/run-fuzz.py
fi

printf '\n==> Deterministic security tier\n'
./scripts/run-security-tests.py

printf '\n==> Nix configuration and negative-fixture suite\n'
./scripts/nix-config-matrix.sh

printf '\n==> Full-stack appliance suite\n'
run_appliance timeout "${NAS_VM_FULL_SUITE_GUEST_TIMEOUT:-3600}" nas-vm-guest-test /dev/vdb
run_appliance timeout "${NAS_VM_FULL_SUITE_SECRET_TIMEOUT:-900}" nas-vm-secret-adversarial
NAS_INSTALLED_FUZZ_SMOKE=1 \
  run_appliance timeout "${NAS_VM_FULL_SUITE_INSTALLED_TIMEOUT:-300}" \
    python3 tests/vm/adversarial-installed.py >"$work/nas-installed-command-smoke.json"
jq -e '.ok == true and .smoke == true and .commands > 0' \
  "$work/nas-installed-command-smoke.json" >/dev/null

printf '\nFULL NIXOS NAS VM SUITE PASSED\n'
