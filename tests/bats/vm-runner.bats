#!/usr/bin/env bats

setup() {
  work="$BATS_TEST_TMPDIR/work"
  mkdir -p "$work"
  cleanup_lib="$BATS_TEST_DIRNAME/../../scripts/lib/nas-vm-cleanup.sh"
  process_cleanup_lib="$BATS_TEST_DIRNAME/../../scripts/lib/nas-vm-process-cleanup.sh"
  deps_lib="$BATS_TEST_DIRNAME/../../scripts/lib/nas-vm-js-deps.sh"
  failure_injection="$BATS_TEST_DIRNAME/../vm/cleanup-failure-injection.sh"
  resource_injection="$BATS_TEST_DIRNAME/../vm/resource-failure-injection.sh"
  persistent_lifecycle="$BATS_TEST_DIRNAME/../vm/persistent-lifecycle.sh"
}

@test "persistent-start cleanup disarms only after a healthy QEMU startup" {
  run "$persistent_lifecycle"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Persistent QEMU lifecycle contract passed"* ]]
}

@test "real VM cleanup contract survives phase failures, cancellation, and rerun" {
  run "$failure_injection"
  [ "$status" -eq 0 ]
  [[ "$output" == *"VM cleanup/profile failure-injection contract passed"* ]]
}

@test "resource failures retain phase and cleanup observability" {
  run "$resource_injection"
  [ "$status" -eq 0 ]
  [[ "$output" == *"VM resource failure-injection contract passed"* ]]
}

@test "one EXIT trap runs every VM cleanup handler in reverse order" {
  cat >"$work/run.sh" <<SH
#!/usr/bin/env bash
set -Eeuo pipefail
source "$cleanup_lib"
log="$work/cleanup.log"
first() { printf 'first:%s\\n' "\$1" >>"\$log"; }
second() { printf 'second:%s\\n' "\$1" >>"\$log"; }
nas_vm_cleanup_add first
nas_vm_cleanup_add second
trap nas_vm_cleanup_trap EXIT
exit 23
SH
  chmod +x "$work/run.sh"
  run "$work/run.sh"
  [ "$status" -eq 23 ]
  [ "$(cat "$work/cleanup.log")" = $'second:23\nfirst:23' ]
}

@test "cleanup continues after an injected handler failure and preserves the test failure" {
  cat >"$work/run.sh" <<SH
#!/usr/bin/env bash
set -Eeuo pipefail
source "$cleanup_lib"
log="$work/cleanup.log"
broken() { printf 'broken:%s\\n' "\$1" >>"\$log"; return 91; }
survivor() { printf 'survivor:%s\\n' "\$1" >>"\$log"; }
nas_vm_cleanup_add survivor
nas_vm_cleanup_add broken
trap nas_vm_cleanup_trap EXIT
exit 17
SH
  chmod +x "$work/run.sh"
  run "$work/run.sh"
  [ "$status" -eq 17 ]
  [ "$(cat "$work/cleanup.log")" = $'broken:17\nsurvivor:17' ]
  [[ "$output" == *"VM-CLEANUP-HANDLER-FAILURE: broken=91"* ]]
}

@test "failed JavaScript dependency setup removes its run-owned partial directory" {
  repo="$work/repo"
  mkdir -p "$repo/tests/js-fuzz"
  cat >"$work/run.sh" <<SH
#!/usr/bin/env bash
set -Eeuo pipefail
source "$deps_lib"
trap 'status=\$?; nas_vm_js_deps_cleanup "\$status"; exit "\$status"' EXIT
NAS_FULL_SUITE_TEST_FAILURE=after-js-deps-directory
nas_vm_js_deps_prepare "$repo"
SH
  chmod +x "$work/run.sh"
  run "$work/run.sh"
  [ "$status" -eq 97 ]
  [ ! -e "$repo/tests/js-fuzz/node_modules" ]
}

@test "successful JavaScript dependency setup is also owned and cleaned" {
  repo="$work/repo"
  fast_check="$work/fast-check"
  mkdir -p "$repo/tests/js-fuzz" "$fast_check"
  cat >"$work/run.sh" <<SH
#!/usr/bin/env bash
set -Eeuo pipefail
source "$deps_lib"
trap 'status=\$?; nas_vm_js_deps_cleanup "\$status"; exit "\$status"' EXIT
nas_vm_js_deps_prepare "$repo" "$fast_check"
test -L "$repo/tests/js-fuzz/node_modules/fast-check"
SH
  chmod +x "$work/run.sh"
  run "$work/run.sh"
  [ "$status" -eq 0 ]
  [ ! -e "$repo/tests/js-fuzz/node_modules" ]
}

@test "full-suite cleanup removes its work directory after a failed run" {
  cat >"$work/run.sh" <<SH
#!/usr/bin/env bash
set -Eeuo pipefail
source "$deps_lib"
work_dir="$work/owned-work"
mkdir -p "\$work_dir"
printf '%s\n' "\$work_dir" >"$work/work-path"
cleanup() {
  local status=\$?
  nas_vm_js_deps_cleanup "\$status" || :
  rm -rf -- "\$work_dir"
  return "\$status"
}

trap cleanup EXIT
exit 43
SH
  chmod +x "$work/run.sh"
  run "$work/run.sh"
  [ "$status" -eq 43 ]
  [ ! -e "$work/owned-work" ]
}

@test "process cleanup escalates from TERM to KILL within its grace period" {
  run bash -c '
    set -Eeuo pipefail
    source "$1"
    (trap "" TERM; sleep 60) &
    pid=$!
    nas_vm_stop_process "$pid" 1
    ! kill -0 "$pid" 2>/dev/null
  ' process-cleanup "$process_cleanup_lib"
  [ "$status" -eq 0 ]
}

@test "JavaScript dependency cleanup reports removal failures after a successful test" {
  run bash -c '
    set -Eeuo pipefail
    source "$1"
    work=$(mktemp -d)
    trap "rm -rf -- \"$work\"" EXIT
    nas_vm_js_deps_remove() { return 91; }
    mkdir -p "$work/tests/js-fuzz" "$work/fast-check"
    nas_vm_js_deps_prepare "$work" "$work/fast-check"
    set +e
    nas_vm_js_deps_cleanup 0
    rc=$?
    set -e
    [[ "$rc" -eq 91 ]]
  ' js-deps "$BATS_TEST_DIRNAME/../../scripts/lib/nas-vm-js-deps.sh"
  [ "$status" -eq 0 ]
}
