#!/usr/bin/env bats

setup() {
  work="$BATS_TEST_TMPDIR/work"
  mkdir -p "$work/bin" "$work/root" "$work/stage"
  touch "$work/root/ready" "$work/root/old" "$work/stage/ready" "$work/stage/new"
  cat > "$work/bin/systemctl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$NAS_TX_LOG"
case "$1" in
  is-active) [[ "${NAS_TX_ACTIVE:-1}" == 1 ]] ;;
  stop) [[ "${NAS_TX_STOP_FAIL:-0}" != 1 ]] ;;
  start) [[ "${NAS_TX_START_FAIL:-0}" != 1 ]] ;;
  *) exit 0 ;;
esac
SH
  chmod +x "$work/bin/systemctl"
  export NAS_SECRET_TX_PRIVILEGE=""
  export NAS_SECRET_TX_SYSTEMCTL="$work/bin/systemctl"
  export NAS_TX_LOG="$work/systemctl.log"
  source "$BATS_TEST_DIRNAME/../../scripts/lib/nas-secret-transaction.sh"
}

@test "successful swap commits the staged tree" {
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  nas_secret_tx_swap
  nas_secret_tx_systemctl start nas-protected-services.target
  nas_secret_tx_commit
  [ -f "$work/root/new" ]
  [ ! -e "$work/root/old" ]
  [ ! -e "$work/previous" ]
}

@test "failed activation restores the prior tree and active target" {
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  nas_secret_tx_swap
  run nas_secret_tx_cleanup 71
  [ "$status" -eq 71 ]
  [ -f "$work/root/old" ]
  [ ! -e "$work/root/new" ]
  grep -q '^start nas-protected-services.target$' "$NAS_TX_LOG"
}

@test "inactive target remains inactive after rollback" {
  export NAS_TX_ACTIVE=0
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  nas_secret_tx_swap
  run nas_secret_tx_cleanup 72
  [ "$status" -eq 72 ]
  [ -f "$work/root/old" ]
  ! grep -q '^start nas-protected-services.target$' "$NAS_TX_LOG"
}

@test "failure before swap leaves an active protected target untouched" {
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  run nas_secret_tx_cleanup 77
  [ "$status" -eq 77 ]
  [ -f "$work/root/old" ]
  [ -f "$work/root/ready" ]
  [ ! -s "$NAS_TX_LOG" ]
}

@test "failed target restart is reported as incomplete rollback" {
  export NAS_TX_START_FAIL=1
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  nas_secret_tx_swap
  run nas_secret_tx_cleanup 78
  [ "$status" -eq 125 ]
  [ -f "$work/root/old" ]
  [ ! -e "$work/root/new" ]
}

@test "rollback removes a partial staged tree" {
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  NAS_SECRET_TX_NEW_INSTALLED=false
  run nas_secret_tx_cleanup 73
  [ "$status" -eq 73 ]
  [ ! -e "$work/stage" ]
  [ -f "$work/root/old" ]
}

@test "termination after swap restores the prior tree" {
  cat > "$work/signal-test.sh" <<SH
#!/usr/bin/env bash
set -Eeuo pipefail
export NAS_SECRET_TX_PRIVILEGE=""
export NAS_SECRET_TX_SYSTEMCTL="$work/bin/systemctl"
export NAS_TX_LOG="$NAS_TX_LOG"
source "$BATS_TEST_DIRNAME/../../scripts/lib/nas-secret-transaction.sh"
nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
trap 'rc=143; nas_secret_tx_cleanup "\$rc"; exit "\$rc"' TERM
nas_secret_tx_swap
kill -TERM \$\$
SH
  chmod +x "$work/signal-test.sh"
  run "$work/signal-test.sh"
  [ "$status" -eq 143 ]
  [ -f "$work/root/old" ]
  [ ! -e "$work/root/new" ]
}

@test "missing previous tree makes rollback incomplete" {
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  nas_secret_tx_swap
  rm -rf "$work/previous"
  run nas_secret_tx_cleanup 80
  [ "$status" -eq 125 ]
  [ ! -e "$work/root/new" ]
  ! grep -q '^start nas-protected-services.target$' "$NAS_TX_LOG"
}

@test "missing ready marker keeps protected services stopped" {
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  nas_secret_tx_swap
  rm -f "$work/previous/ready"
  run nas_secret_tx_cleanup 81
  [ "$status" -eq 125 ]
  [ -f "$work/root/old" ]
  ! grep -q '^start nas-protected-services.target$' "$NAS_TX_LOG"
}

@test "symlinked stage is rejected before stopping services" {
  mkdir "$work/outside"
  touch "$work/outside/ready" "$work/outside/new"
  rm -rf "$work/stage"
  ln -s "$work/outside" "$work/stage"
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  run nas_secret_tx_swap
  [ "$status" -ne 0 ]
  [ -f "$work/root/old" ]
  [ -f "$work/outside/new" ]
  [ ! -s "$NAS_TX_LOG" ]
}

@test "preexisting previous tree is rejected before stopping services" {
  mkdir "$work/previous"
  touch "$work/previous/stale"
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  run nas_secret_tx_swap
  [ "$status" -ne 0 ]
  [ -f "$work/root/old" ]
  [ -f "$work/stage/new" ]
  [ -f "$work/previous/stale" ]
  [ ! -s "$NAS_TX_LOG" ]
}

@test "invalid transaction path topology is rejected" {
  run nas_secret_tx_init "$work/root" "$work/root/new" "$work/previous"
  [ "$status" -ne 0 ]
  run nas_secret_tx_init / "$work/stage" "$work/previous"
  [ "$status" -ne 0 ]
  run nas_secret_tx_init "$work/root" "$work/stage" "$work/stage/previous"
  [ "$status" -ne 0 ]
}

@test "commit cannot skip the swap phase" {
  nas_secret_tx_init "$work/root" "$work/stage" "$work/previous"
  run nas_secret_tx_commit
  [ "$status" -ne 0 ]
  [ -f "$work/root/old" ]
  [ -f "$work/stage/new" ]
}

@test "option-like and non-target systemd units are rejected" {
  run nas_secret_tx_init "$work/root" "$work/stage" "$work/previous" '--root=/tmp.target'
  [ "$status" -ne 0 ]
  run nas_secret_tx_init "$work/root" "$work/stage" "$work/previous" bad.service
  [ "$status" -ne 0 ]
  [ ! -s "$NAS_TX_LOG" ]
}
