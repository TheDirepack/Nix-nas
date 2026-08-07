#!/usr/bin/env bash

nas_secret_tx_privileged() {
  local privilege="${NAS_SECRET_TX_PRIVILEGE-sudo}"
  if [[ -n "$privilege" ]]; then
    "$privilege" "$@"
  else
    "$@"
  fi
}

nas_secret_tx_systemctl() {
  nas_secret_tx_privileged "${NAS_SECRET_TX_SYSTEMCTL:-systemctl}" "$@"
}

# Transaction phases:
# Secret activation transaction phases:
#   initialized -> stopping -> stopped -> old-moved -> new-installed -> committed
# Recovery before old-moved may restart the prior consumers directly. After
# old-moved, rollback must restore the previous secret tree before restarting.
# committed is terminal: the new tree is authoritative and cleanup may remove
# the old staging copy. No phase may skip forward across a filesystem swap.
# A failure before commit runs rollback, which removes the staged/new tree, restores
# the previous tree when one existed, and restarts the protected target only when it
# was active before the swap and the restored secret tree is marked ready. A rollback
# that cannot fully restore state returns 125 through nas_secret_tx_cleanup so callers
# must treat the appliance as requiring manual recovery.

nas_secret_tx_init() {
  NAS_SECRET_TX_ROOT=$1
  NAS_SECRET_TX_STAGE=$2
  NAS_SECRET_TX_PREVIOUS=$3
  NAS_SECRET_TX_TARGET=${4:-nas-protected-services.target}
  NAS_SECRET_TX_DIRECTORY=${5:-}
  NAS_SECRET_TX_PHASE=initialized
  NAS_SECRET_TX_SWAP_STARTED=false
  NAS_SECRET_TX_OLD_MOVED=false
  NAS_SECRET_TX_NEW_INSTALLED=false
  NAS_SECRET_TX_COMMITTED=false
  NAS_SECRET_TX_WAS_ACTIVE=false
}

nas_secret_tx_swap() {
  [[ "$NAS_SECRET_TX_PHASE" == initialized ]] || {
    printf 'nas-secret-transaction: invalid swap phase: %s\n' "$NAS_SECRET_TX_PHASE" >&2
    return 1
  }
  nas_secret_tx_systemctl is-active --quiet "$NAS_SECRET_TX_TARGET" && NAS_SECRET_TX_WAS_ACTIVE=true || true
  NAS_SECRET_TX_SWAP_STARTED=true
  NAS_SECRET_TX_PHASE=stopping
  nas_secret_tx_systemctl stop "$NAS_SECRET_TX_TARGET"
  NAS_SECRET_TX_PHASE=stopped
  if nas_secret_tx_privileged test -d "$NAS_SECRET_TX_ROOT"; then
    nas_secret_tx_privileged test ! -e "$NAS_SECRET_TX_PREVIOUS" || {
      printf 'nas-secret-transaction: previous tree already exists: %s\n' "$NAS_SECRET_TX_PREVIOUS" >&2
      return 1
    }
    nas_secret_tx_privileged mv "$NAS_SECRET_TX_ROOT" "$NAS_SECRET_TX_PREVIOUS"
    NAS_SECRET_TX_OLD_MOVED=true
  fi
  NAS_SECRET_TX_PHASE=old-moved
  nas_secret_tx_privileged mv "$NAS_SECRET_TX_STAGE" "$NAS_SECRET_TX_ROOT"
  NAS_SECRET_TX_NEW_INSTALLED=true
  NAS_SECRET_TX_PHASE=new-installed
}

nas_secret_tx_remove_directory() {
  if [[ -n "${NAS_SECRET_TX_DIRECTORY:-}" ]]; then
    nas_secret_tx_privileged rm -rf "$NAS_SECRET_TX_DIRECTORY"
  fi
}

nas_secret_tx_rollback() {
  local failed=false
  if [[ "$NAS_SECRET_TX_SWAP_STARTED" != true ]]; then
    nas_secret_tx_privileged rm -rf "$NAS_SECRET_TX_STAGE" || failed=true
    nas_secret_tx_remove_directory || failed=true
    "$failed" && return 1 || return 0
  fi

  nas_secret_tx_systemctl stop "$NAS_SECRET_TX_TARGET" >/dev/null 2>&1 || failed=true
  if [[ "$NAS_SECRET_TX_NEW_INSTALLED" == true ]]; then
    nas_secret_tx_privileged rm -rf "$NAS_SECRET_TX_ROOT" || failed=true
  fi
  if [[ "$NAS_SECRET_TX_OLD_MOVED" == true ]] && nas_secret_tx_privileged test -d "$NAS_SECRET_TX_PREVIOUS"; then
    nas_secret_tx_privileged mv "$NAS_SECRET_TX_PREVIOUS" "$NAS_SECRET_TX_ROOT" || failed=true
  fi
  nas_secret_tx_privileged rm -rf "$NAS_SECRET_TX_STAGE" || failed=true
  if [[ "$NAS_SECRET_TX_WAS_ACTIVE" == true ]] && nas_secret_tx_privileged test -f "$NAS_SECRET_TX_ROOT/ready"; then
    nas_secret_tx_systemctl start "$NAS_SECRET_TX_TARGET" >/dev/null 2>&1 || failed=true
  fi
  nas_secret_tx_remove_directory || failed=true
  NAS_SECRET_TX_PHASE=rolled-back
  if "$failed"; then
    printf 'nas-secret-transaction: rollback was incomplete; inspect systemd and %s\n' "$NAS_SECRET_TX_ROOT" >&2
    return 1
  fi
}

nas_secret_tx_commit() {
  NAS_SECRET_TX_COMMITTED=true
  NAS_SECRET_TX_PHASE=committed
  nas_secret_tx_privileged rm -rf "$NAS_SECRET_TX_PREVIOUS"
  nas_secret_tx_remove_directory
}

nas_secret_tx_cleanup() {
  local rc=$1
  if [[ $rc -ne 0 && "$NAS_SECRET_TX_COMMITTED" != true ]]; then
    nas_secret_tx_rollback || return 125
  fi
  return "$rc"
}
