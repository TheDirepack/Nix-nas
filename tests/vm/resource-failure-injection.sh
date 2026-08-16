#!/usr/bin/env bash
# Cleanup handlers are registered by name and invoked indirectly by the EXIT trap.
# shellcheck disable=SC2317
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nas-vm-resource-contract.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

# shellcheck disable=SC1091
source "$ROOT/scripts/lib/nas-vm-cleanup.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/nas-vm-profile.sh"
# shellcheck disable=SC1091
source "$ROOT/tests/vm/timeout-budget.sh"

fake_tool() {
  local name=$1 status=$2 delay=${3:-0}
  printf '#!/usr/bin/env bash\nsleep %q\nexit %q\n' "$delay" "$status" >"$WORK/$name"
  chmod +x "$WORK/$name"
}

fake_tool curl 6
fake_tool qemu-system-x86_64 125
fake_tool nix 100
fake_tool fallocate 28
fake_tool systemctl 0 5

run_case() {
  local phase=$1 expected=$2 command_name=$3
  shift 3
  local case_dir="$WORK/$phase"
  mkdir -p "$case_dir/state" "$case_dir/evidence"
  (
    set -Eeuo pipefail
    # shellcheck disable=SC1091
    source "$ROOT/scripts/lib/nas-vm-cleanup.sh"
    # shellcheck disable=SC1091
    source "$ROOT/scripts/lib/nas-vm-profile.sh"
    # shellcheck disable=SC1091
    source "$ROOT/tests/vm/timeout-budget.sh"
    export NAS_VM_PROFILE_OUTPUT="$case_dir/profile.log"
    export NAS_VM_CLEANUP_OUTPUT="$case_dir/cleanup.log"
    export NAS_VM_ARTIFACT_PATH="$case_dir/evidence/resource.json"
    # shellcheck disable=SC2329
    cleanup_state() { rm -rf -- "$case_dir/state"; return 0; }
    nas_vm_profile_install
    nas_vm_cleanup_add cleanup_state
    nas_vm_profile_command "log \"$phase\""
    printf -v command_line '%q ' "$command_name" "$@"
    # shellcheck disable=SC2034
    NAS_VM_LAST_COMMAND="${command_line% }"
    trap - DEBUG
    if "$@"; then
      printf 'resource contract: %s unexpectedly succeeded\n' "$phase" >&2
      exit 1
    else
      status=$?
      [[ $status -eq $expected ]] || {
        printf 'resource contract: %s returned %s, expected %s\n' "$phase" "$status" "$expected" >&2
        exit 1
      }
      exit "$status"
    fi
  )
}

export PATH="$WORK:$PATH"
declare -a CASES=(
  "missing-binary|127|missing-nas-command|missing-nas-command"
  "network-unavailable|6|curl|curl --fail https://unavailable.invalid"
  "qemu-startup|125|qemu-system-x86_64|qemu-system-x86_64 -display none"
  "nix-build|100|nix|nix build .#missing"
  "disk-full|28|fallocate|fallocate -l 1G $WORK/disk"
  "systemd-hung|124|timeout|timeout --foreground 1 systemctl start nas-test.service"
)

for entry in "${CASES[@]}"; do
  IFS='|' read -r phase expected command_name command_line <<<"$entry"
  # shellcheck disable=SC2086
  if run_case "$phase" "$expected" "$command_name" $command_line; then
    printf 'resource contract: %s unexpectedly passed\n' "$phase" >&2
    exit 1
  else
    status=$?
  fi
  [[ $status -eq $expected ]] || exit 1
  case_dir="$WORK/$phase"
  grep -Fq "VM-PHASE-START: $phase" "$case_dir/profile.log"
  grep -Fq "VM-PHASE-TIMING: $phase:" "$case_dir/profile.log"
  grep -Fq "VM-LAST-COMMAND: $command_name" "$case_dir/profile.log"
  grep -Fq "VM-ARTIFACT-PATH: $case_dir/evidence/resource.json" "$case_dir/profile.log"
  grep -Fq 'VM-CLEANUP-STATUS: 0' "$case_dir/cleanup.log"
  test ! -e "$case_dir/state"
done

printf 'VM resource failure-injection contract passed\n'
