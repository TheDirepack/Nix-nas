#!/usr/bin/env bash
# Disposable native guard timer/outcome fixture (WS06).
# Runs only with unique nas-guard-test-* units and an isolated state dir.
# Never touches production nas-v2-apply-rollback-* timers or the real guard dir.
set -Eeuo pipefail

SRC="${NAS_GUARD_SRC:-/var/lib/nas-test/repo/services}"
PY="${NAS_GUARD_PYTHON:-$(command -v python3 2>/dev/null || ls /nix/store/*python3*/bin/python3 2>/dev/null | head -n 1)}"
[[ -n "$PY" && -x "$PY" ]] || { printf 'GUARD-FIXTURE FAIL: no python3 found\n' >&2; exit 1; }
GUARD="$PY $SRC/nas_guarded_apply.py"
SH="$(command -v sh)"
[[ -n "$SH" && -x "$SH" ]] || fail "no sh found"
TOUCH="$(command -v touch)"
[[ -n "$TOUCH" && -x "$TOUCH" ]] || fail "no touch found"
STATE_ROOT="$(mktemp -d /tmp/nas-guard-test-state.XXXXXX)"
SUFFIX="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
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
  got=$($PY "$SRC/nas_guarded_apply.py" --state-dir "$STATE_ROOT" --unit "$unit" status | $PY -c 'import json,sys; print(json.load(sys.stdin)["state"])')
  [[ "$got" == "$expected" ]] || fail "unit $unit state=$got expected=$expected"
  log "unit $unit state=$got as expected"
}

# 1. Never-fired cancellation succeeds and never runs rollback.
U="$UNIT_BASE-never"
M="$MARKERS/never"
$GUARD --state-dir "$STATE_ROOT" --unit "$U" arm --timeout 120 -- "$SH" "-c" "$TOUCH $M; exit 0" >/dev/null
$GUARD --state-dir "$STATE_ROOT" --unit "$U" cancel >/dev/null
assert_state "$U" cancelled
[[ ! -e "$M" ]] || fail "never-fired rollback must not run"

# 2. Short timer fires to completion; cancel then reports completed, not success.
U="$UNIT_BASE-done"
M="$MARKERS/done"
$GUARD --state-dir "$STATE_ROOT" --unit "$U" arm --timeout 2 -- "$SH" "-c" "$TOUCH $M; exit 0" >/dev/null
sleep 5
assert_state "$U" completed
[[ -e "$M" ]] || fail "fired rollback marker missing"
if $GUARD --state-dir "$STATE_ROOT" --unit "$U" cancel >/dev/null 2>&1; then
  fail "cancel after completed rollback must not succeed"
fi
log "completed guard correctly blocks cancel"

# 3. Failed firing stays inspectable; re-arm blocked until collect.
U="$UNIT_BASE-fail"
M="$MARKERS/failed"
$GUARD --state-dir "$STATE_ROOT" --unit "$U" arm --timeout 2 -- "$SH" "-c" "$TOUCH $M; exit 3" >/dev/null
sleep 5
assert_state "$U" failed
[[ -e "$M" ]] || fail "failed rollback marker missing"
if $GUARD --state-dir "$STATE_ROOT" --unit "$U" cancel >/dev/null 2>&1; then
  fail "cancel after failed rollback must not succeed"
fi
if $GUARD --state-dir "$STATE_ROOT" --unit "$U" arm --timeout 60 -- "$SH" "-c" "exit 0" >/dev/null 2>&1; then
  fail "re-arm over unresolved failure must not succeed"
fi
$GUARD --state-dir "$STATE_ROOT" --unit "$U" collect >/dev/null
assert_state "$U" collected
$GUARD --state-dir "$STATE_ROOT" --unit "$U" arm --timeout 60 -- "$SH" "-c" "exit 0" >/dev/null
assert_state "$U" armed
$GUARD --state-dir "$STATE_ROOT" --unit "$U" cancel >/dev/null
log "failed -> collected -> re-arm cycle passes"

# 4. Cancel wins the race: late firing aborts without rollback.
U="$UNIT_BASE-race"
M="$MARKERS/race"
$GUARD --state-dir "$STATE_ROOT" --unit "$U" arm --timeout 60 -- "$SH" "-c" "$TOUCH $M; exit 0" >/dev/null
$GUARD --state-dir "$STATE_ROOT" --unit "$U" cancel >/dev/null
out=$($GUARD --state-dir "$STATE_ROOT" --unit "$U" fired -- "$SH" "-c" "$TOUCH $M; exit 0")
echo "$out" | grep -q cancelled || fail "late firing after cancel must report cancelled"
[[ ! -e "$M" ]] || fail "late firing after cancel must not run rollback"

log "ALL NATIVE GUARD INTERLEAVINGS PASS"
