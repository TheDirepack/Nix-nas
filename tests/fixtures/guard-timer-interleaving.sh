#!/usr/bin/env bash
# Disposable native guard timer/outcome fixture (WS06).
# Runs only with unique nas-guard-test-* units and an isolated state dir.
# Never touches production nas-v2-apply-rollback-* timers or the real guard dir.
set -Eeuo pipefail

SRC="${NAS_GUARD_SRC:-/var/lib/nas-test/repo/services}"
GUARD="python3 $SRC/nas_guarded_apply.py"
STATE_ROOT="$(mktemp -d /tmp/nas-guard-test-state.XXXXXX)"
SUFFIX="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
UNIT_BASE="nas-guard-test-$SUFFIX"
MARKERS="$(mktemp -d /tmp/nas-guard-test-markers.XXXXXX)"

log() { printf 'GUARD-FIXTURE: %s\n' "$*"; }
fail() { printf 'GUARD-FIXTURE FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  for u in "$UNIT_BASE"-never "$UNIT_BASE"-done "$UNIT_BASE"-fail "$UNIT_BASE"-race; do
    systemctl stop "$u.timer" >/dev/null 2>&1 || true
  done
  rm -rf -- "$STATE_ROOT" "$MARKERS"
}
trap cleanup EXIT

assert_state() {
  local unit=$1 expected=$2
  local got
  got=$(python3 "$SRC/nas_guarded_apply.py" --state-dir "$STATE_ROOT" status --unit "$unit" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')
  [[ "$got" == "$expected" ]] || fail "unit $unit state=$got expected=$expected"
  log "unit $unit state=$got as expected"
}

# 1. Never-fired cancellation succeeds and never runs rollback.
U="$UNIT_BASE-never"
M="$MARKERS/never"
$GUARD --state-dir "$STATE_ROOT" arm --unit "$U" --timeout 120 -- "sh" "-c" "touch $M; exit 0" >/dev/null
$GUARD --state-dir "$STATE_ROOT" cancel --unit "$U" >/dev/null
assert_state "$U" cancelled
[[ ! -e "$M" ]] || fail "never-fired rollback must not run"

# 2. Short timer fires to completion; cancel then reports completed, not success.
U="$UNIT_BASE-done"
M="$MARKERS/done"
$GUARD --state-dir "$STATE_ROOT" arm --unit "$U" --timeout 2 -- "sh" "-c" "touch $M; exit 0" >/dev/null
sleep 5
assert_state "$U" completed
[[ -e "$M" ]] || fail "fired rollback marker missing"
if $GUARD --state-dir "$STATE_ROOT" cancel --unit "$U" >/dev/null 2>&1; then
  fail "cancel after completed rollback must not succeed"
fi
log "completed guard correctly blocks cancel"

# 3. Failed firing stays inspectable; re-arm blocked until collect.
U="$UNIT_BASE-fail"
M="$MARKERS/failed"
$GUARD --state-dir "$STATE_ROOT" arm --unit "$U" --timeout 2 -- "sh" "-c" "touch $M; exit 3" >/dev/null
sleep 5
assert_state "$U" failed
[[ -e "$M" ]] || fail "failed rollback marker missing"
if $GUARD --state-dir "$STATE_ROOT" cancel --unit "$U" >/dev/null 2>&1; then
  fail "cancel after failed rollback must not succeed"
fi
if $GUARD --state-dir "$STATE_ROOT" arm --unit "$U" --timeout 60 -- "sh" "-c" "exit 0" >/dev/null 2>&1; then
  fail "re-arm over unresolved failure must not succeed"
fi
$GUARD --state-dir "$STATE_ROOT" collect --unit "$U" >/dev/null
assert_state "$U" collected
$GUARD --state-dir "$STATE_ROOT" arm --unit "$U" --timeout 60 -- "sh" "-c" "exit 0" >/dev/null
assert_state "$U" armed
$GUARD --state-dir "$STATE_ROOT" cancel --unit "$U" >/dev/null
log "failed -> collected -> re-arm cycle passes"

# 4. Cancel wins the race: late firing aborts without rollback.
U="$UNIT_BASE-race"
M="$MARKERS/race"
$GUARD --state-dir "$STATE_ROOT" arm --unit "$U" --timeout 60 -- "sh" "-c" "touch $M; exit 0" >/dev/null
$GUARD --state-dir "$STATE_ROOT" cancel --unit "$U" >/dev/null
out=$($GUARD --state-dir "$STATE_ROOT" fired --unit "$U" -- "sh" "-c" "touch $M; exit 0")
echo "$out" | grep -q cancelled || fail "late firing after cancel must report cancelled"
[[ ! -e "$M" ]] || fail "late firing after cancel must not run rollback"

log "ALL NATIVE GUARD INTERLEAVINGS PASS"
