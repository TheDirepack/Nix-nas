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

nas_secret_tx_realpath_lexical() {
  local value=$1
  [[ "$value" == /* ]] || return 1
  python3 - "$value" <<'PY'
import os
import sys
print(os.path.normpath(sys.argv[1]))
PY
}

nas_secret_tx_paths_overlap() {
  local left=$1 right=$2
  [[ "$left" == "$right" || "$left" == "$right/"* || "$right" == "$left/"* ]]
}

nas_secret_tx_validate_paths() {
  local root stage previous directory normalized
  root="$(nas_secret_tx_realpath_lexical "$1")" || {
    printf 'nas-secret-transaction: secret root must be an absolute path: %s\n' "$1" >&2
    return 1
  }
  stage="$(nas_secret_tx_realpath_lexical "$2")" || {
    printf 'nas-secret-transaction: staged tree must be an absolute path: %s\n' "$2" >&2
    return 1
  }
  previous="$(nas_secret_tx_realpath_lexical "$3")" || {
    printf 'nas-secret-transaction: previous tree must be an absolute path: %s\n' "$3" >&2
    return 1
  }
  directory="${4:-}"
  if [[ -n "$directory" ]]; then
    normalized="$(nas_secret_tx_realpath_lexical "$directory")" || {
      printf 'nas-secret-transaction: transaction directory must be an absolute path: %s\n' "$directory" >&2
      return 1
    }
    directory=$normalized
  fi
  for value in "$root" "$stage" "$previous"; do
    [[ "$value" != / ]] || {
      printf 'nas-secret-transaction: refusing to operate on filesystem root\n' >&2
      return 1
    }
  done
  nas_secret_tx_paths_overlap "$root" "$stage" && {
    printf 'nas-secret-transaction: secret root and staged tree must be disjoint\n' >&2
    return 1
  }
  nas_secret_tx_paths_overlap "$root" "$previous" && {
    printf 'nas-secret-transaction: secret root and previous tree must be disjoint\n' >&2
    return 1
  }
  nas_secret_tx_paths_overlap "$stage" "$previous" && {
    printf 'nas-secret-transaction: staged and previous trees must be disjoint\n' >&2
    return 1
  }
  if [[ -n "$directory" ]]; then
    [[ "$directory" != / ]] || {
      printf 'nas-secret-transaction: refusing filesystem root as transaction directory\n' >&2
      return 1
    }
    # The transaction directory may contain stage/previous, but it must never contain
    # the live secret root or itself be beneath the live root.
    if [[ "$root" == "$directory" || "$root" == "$directory/"* || "$directory" == "$root/"* ]]; then
      printf 'nas-secret-transaction: transaction directory must be disjoint from the live secret root\n' >&2
      return 1
    fi
  fi
  NAS_SECRET_TX_ROOT=$root
  NAS_SECRET_TX_STAGE=$stage
  NAS_SECRET_TX_PREVIOUS=$previous
  NAS_SECRET_TX_DIRECTORY=$directory
}

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
  nas_secret_tx_validate_paths "$1" "$2" "$3" "${5:-}" || return 1
  NAS_SECRET_TX_TARGET=${4:-nas-protected-services.target}
  [[ -n "$NAS_SECRET_TX_TARGET" && "$NAS_SECRET_TX_TARGET" != *$'\n'* && "$NAS_SECRET_TX_TARGET" != *$'\r'* ]] || {
    printf 'nas-secret-transaction: invalid protected target name\n' >&2
    return 1
  }
  NAS_SECRET_TX_PHASE=initialized
  NAS_SECRET_TX_SWAP_STARTED=false
  NAS_SECRET_TX_OLD_MOVED=false
  NAS_SECRET_TX_NEW_INSTALLED=false
  NAS_SECRET_TX_COMMITTED=false
  NAS_SECRET_TX_WAS_ACTIVE=false
}

nas_secret_tx_swap() {
  [[ "${NAS_SECRET_TX_PHASE:-}" == initialized ]] || {
    printf 'nas-secret-transaction: invalid swap phase: %s\n' "${NAS_SECRET_TX_PHASE:-unset}" >&2
    return 1
  }
  nas_secret_tx_privileged test -d "$NAS_SECRET_TX_STAGE" || {
    printf 'nas-secret-transaction: staged tree is unavailable: %s\n' "$NAS_SECRET_TX_STAGE" >&2
    return 1
  }
  nas_secret_tx_privileged test ! -e "$NAS_SECRET_TX_PREVIOUS" || {
    printf 'nas-secret-transaction: previous tree already exists: %s\n' "$NAS_SECRET_TX_PREVIOUS" >&2
    return 1
  }
  nas_secret_tx_systemctl is-active --quiet "$NAS_SECRET_TX_TARGET" && NAS_SECRET_TX_WAS_ACTIVE=true || true
  NAS_SECRET_TX_SWAP_STARTED=true
  NAS_SECRET_TX_PHASE=stopping
  nas_secret_tx_systemctl stop "$NAS_SECRET_TX_TARGET"
  NAS_SECRET_TX_PHASE=stopped
  if nas_secret_tx_privileged test -d "$NAS_SECRET_TX_ROOT"; then
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
    nas_secret_tx_privileged rm -rf -- "$NAS_SECRET_TX_DIRECTORY"
  fi
}

nas_secret_tx_rollback() {
  local failed=false
  [[ "${NAS_SECRET_TX_COMMITTED:-false}" != true ]] || {
    printf 'nas-secret-transaction: refusing rollback after commit\n' >&2
    return 1
  }
  if [[ "${NAS_SECRET_TX_SWAP_STARTED:-false}" != true ]]; then
    nas_secret_tx_privileged rm -rf -- "$NAS_SECRET_TX_STAGE" || failed=true
    nas_secret_tx_remove_directory || failed=true
    "$failed" && return 1 || return 0
  fi

  nas_secret_tx_systemctl stop "$NAS_SECRET_TX_TARGET" >/dev/null 2>&1 || failed=true
  if [[ "$NAS_SECRET_TX_NEW_INSTALLED" == true ]]; then
    nas_secret_tx_privileged rm -rf -- "$NAS_SECRET_TX_ROOT" || failed=true
  fi
  if [[ "$NAS_SECRET_TX_OLD_MOVED" == true ]]; then
    if nas_secret_tx_privileged test -d "$NAS_SECRET_TX_PREVIOUS"; then
      nas_secret_tx_privileged mv "$NAS_SECRET_TX_PREVIOUS" "$NAS_SECRET_TX_ROOT" || failed=true
    else
      printf 'nas-secret-transaction: previous secret tree disappeared during rollback: %s\n' "$NAS_SECRET_TX_PREVIOUS" >&2
      failed=true
    fi
  fi
  nas_secret_tx_privileged rm -rf -- "$NAS_SECRET_TX_STAGE" || failed=true
  if [[ "$NAS_SECRET_TX_WAS_ACTIVE" == true ]]; then
    if nas_secret_tx_privileged test -f "$NAS_SECRET_TX_ROOT/ready"; then
      nas_secret_tx_systemctl start "$NAS_SECRET_TX_TARGET" >/dev/null 2>&1 || failed=true
    else
      printf 'nas-secret-transaction: restored secret tree is not ready; protected target remains stopped\n' >&2
      failed=true
    fi
  fi
  nas_secret_tx_remove_directory || failed=true
  NAS_SECRET_TX_PHASE=rolled-back
  if "$failed"; then
    printf 'nas-secret-transaction: rollback was incomplete; inspect systemd and %s\n' "$NAS_SECRET_TX_ROOT" >&2
    return 1
  fi
}

nas_secret_tx_commit() {
  [[ "${NAS_SECRET_TX_PHASE:-}" == new-installed && "${NAS_SECRET_TX_NEW_INSTALLED:-false}" == true ]] || {
    printf 'nas-secret-transaction: invalid commit phase: %s\n' "${NAS_SECRET_TX_PHASE:-unset}" >&2
    return 1
  }
  [[ "${NAS_SECRET_TX_COMMITTED:-false}" != true ]] || {
    printf 'nas-secret-transaction: transaction is already committed\n' >&2
    return 1
  }
  NAS_SECRET_TX_COMMITTED=true
  NAS_SECRET_TX_PHASE=committed
  nas_secret_tx_privileged rm -rf -- "$NAS_SECRET_TX_PREVIOUS"
  nas_secret_tx_remove_directory
}

nas_secret_tx_cleanup() {
  local rc=$1
  [[ "$rc" =~ ^[0-9]+$ ]] || {
    printf 'nas-secret-transaction: cleanup status must be numeric\n' >&2
    return 125
  }
  if [[ $rc -ne 0 && "${NAS_SECRET_TX_COMMITTED:-false}" != true ]]; then
    nas_secret_tx_rollback || return 125
  fi
  return "$rc"
}
