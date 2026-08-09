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
  # Canonicalize dot/dot-dot lexically without following symlinks. Following them
  # here would hide a symlink from the explicit lstat-style checks below.
  realpath -m -s -- "$value"
}

nas_secret_tx_parent_is_physical() {
  local value=$1 parent lexical physical
  parent="$(dirname -- "$value")" || return 1
  lexical="$(realpath -m -s -- "$parent")" || return 1
  physical="$(realpath -e -- "$parent")" || return 1
  [[ "$lexical" == "$physical" ]]
}

nas_secret_tx_paths_overlap() {
  local left=$1 right=$2
  [[ "$left" == "$right" || "$left" == "$right/"* || "$right" == "$left/"* ]]
}

nas_secret_tx_validate_paths() {
  local root stage previous directory normalized physical_directory value
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
    nas_secret_tx_parent_is_physical "$value" || {
      printf 'nas-secret-transaction: parent path is missing or traverses a symlink: %s\n' "$value" >&2
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
    [[ -d "$directory" && ! -L "$directory" ]] || {
      printf 'nas-secret-transaction: transaction directory must be a real directory: %s\n' "$directory" >&2
      return 1
    }
    physical_directory="$(realpath -e -- "$directory")" || {
      printf 'nas-secret-transaction: transaction directory cannot be resolved safely: %s\n' "$directory" >&2
      return 1
    }
    [[ "$physical_directory" == "$directory" ]] || {
      printf 'nas-secret-transaction: transaction directory traverses a symlink: %s\n' "$directory" >&2
      return 1
    }
    # The transaction directory may contain stage/previous, but it must never contain
    # the live secret root or itself be beneath the live root.
    if nas_secret_tx_paths_overlap "$root" "$directory"; then
      printf 'nas-secret-transaction: transaction directory must be disjoint from the live secret root\n' >&2
      return 1
    fi
    [[ "$(dirname -- "$stage")" == "$directory" && "$(dirname -- "$previous")" == "$directory" ]] || {
      printf 'nas-secret-transaction: staged and previous trees must be direct children of the transaction directory\n' >&2
      return 1
    }
  fi
  NAS_SECRET_TX_ROOT=$root
  NAS_SECRET_TX_STAGE=$stage
  NAS_SECRET_TX_PREVIOUS=$previous
  NAS_SECRET_TX_DIRECTORY=$directory
}

# Secret activation transaction phases:
#   initialized -> stopping -> stopped -> old-moved -> new-installed -> committing -> committed
# Recovery before old-moved may restart the prior consumers directly. After
# old-moved, rollback must restore the previous secret tree before restarting.
# Once commit starts deleting the previous tree, rollback is no longer safe; any
# cleanup failure is surfaced as status 125 with the new tree remaining authoritative.
# A failure before commit runs rollback, which removes the staged/new tree, restores
# the previous tree when one existed, and restarts the protected target only when it
# was active before the swap and the restored secret tree is marked ready. A rollback
# that cannot fully restore state returns 125 through nas_secret_tx_cleanup so callers
# must treat the appliance as requiring manual recovery.

nas_secret_tx_init() {
  nas_secret_tx_validate_paths "$1" "$2" "$3" "${5:-}" || return 1
  NAS_SECRET_TX_TARGET=${4:-nas-protected-services.target}
  [[ "$NAS_SECRET_TX_TARGET" =~ ^[A-Za-z0-9_.@:-]+\.target$ && "$NAS_SECRET_TX_TARGET" != -* ]] || {
    printf 'nas-secret-transaction: invalid protected target name: %s\n' "$NAS_SECRET_TX_TARGET" >&2
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
  nas_secret_tx_privileged test ! -L "$NAS_SECRET_TX_STAGE" || {
    printf 'nas-secret-transaction: staged tree must not be a symlink: %s\n' "$NAS_SECRET_TX_STAGE" >&2
    return 1
  }
  nas_secret_tx_privileged test -f "$NAS_SECRET_TX_STAGE/ready" || {
    printf 'nas-secret-transaction: staged tree is missing its ready marker\n' >&2
    return 1
  }
  nas_secret_tx_privileged test ! -L "$NAS_SECRET_TX_STAGE/ready" || {
    printf 'nas-secret-transaction: staged ready marker must not be a symlink\n' >&2
    return 1
  }
  if nas_secret_tx_privileged test -e "$NAS_SECRET_TX_ROOT"; then
    nas_secret_tx_privileged test -d "$NAS_SECRET_TX_ROOT" || {
      printf 'nas-secret-transaction: live secret root is not a directory: %s\n' "$NAS_SECRET_TX_ROOT" >&2
      return 1
    }
    nas_secret_tx_privileged test ! -L "$NAS_SECRET_TX_ROOT" || {
      printf 'nas-secret-transaction: live secret root must not be a symlink: %s\n' "$NAS_SECRET_TX_ROOT" >&2
      return 1
    }
  fi
  nas_secret_tx_privileged test ! -e "$NAS_SECRET_TX_PREVIOUS" || {
    printf 'nas-secret-transaction: previous tree already exists: %s\n' "$NAS_SECRET_TX_PREVIOUS" >&2
    return 1
  }
  if nas_secret_tx_systemctl is-active --quiet "$NAS_SECRET_TX_TARGET"; then
    NAS_SECRET_TX_WAS_ACTIVE=true
  fi

  # Every irreversible operation is checked explicitly. Callers frequently
  # disable errexit around this function so they can capture its status and run
  # rollback; relying on the caller's shell options here would let a failed stop
  # or move fall through and incorrectly advance the transaction phase flags.
  NAS_SECRET_TX_SWAP_STARTED=true
  NAS_SECRET_TX_PHASE=stopping
  nas_secret_tx_systemctl stop "$NAS_SECRET_TX_TARGET" || return $?
  NAS_SECRET_TX_PHASE=stopped
  if nas_secret_tx_privileged test -d "$NAS_SECRET_TX_ROOT"; then
    nas_secret_tx_privileged mv "$NAS_SECRET_TX_ROOT" "$NAS_SECRET_TX_PREVIOUS" || return $?
    NAS_SECRET_TX_OLD_MOVED=true
  fi
  NAS_SECRET_TX_PHASE=old-moved
  nas_secret_tx_privileged mv "$NAS_SECRET_TX_STAGE" "$NAS_SECRET_TX_ROOT" || return $?
  NAS_SECRET_TX_NEW_INSTALLED=true
  NAS_SECRET_TX_PHASE=new-installed
  if ! nas_secret_tx_privileged test -d "$NAS_SECRET_TX_ROOT" \
    || ! nas_secret_tx_privileged test ! -L "$NAS_SECRET_TX_ROOT" \
    || ! nas_secret_tx_privileged test -f "$NAS_SECRET_TX_ROOT/ready" \
    || ! nas_secret_tx_privileged test ! -L "$NAS_SECRET_TX_ROOT/ready"; then
    printf 'nas-secret-transaction: installed secret tree failed post-swap validation\n' >&2
    return 1
  fi
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
    if nas_secret_tx_privileged test -d "$NAS_SECRET_TX_PREVIOUS" && nas_secret_tx_privileged test ! -L "$NAS_SECRET_TX_PREVIOUS"; then
      nas_secret_tx_privileged mv "$NAS_SECRET_TX_PREVIOUS" "$NAS_SECRET_TX_ROOT" || failed=true
    else
      printf 'nas-secret-transaction: previous secret tree disappeared or became unsafe during rollback: %s\n' "$NAS_SECRET_TX_PREVIOUS" >&2
      failed=true
    fi
  fi
  nas_secret_tx_privileged rm -rf -- "$NAS_SECRET_TX_STAGE" || failed=true
  if [[ "$NAS_SECRET_TX_WAS_ACTIVE" == true ]]; then
    if nas_secret_tx_privileged test -f "$NAS_SECRET_TX_ROOT/ready" && nas_secret_tx_privileged test ! -L "$NAS_SECRET_TX_ROOT/ready"; then
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
  # From this point onward rollback is unsafe because cleanup may delete some or
  # all of the prior tree. Mark the new tree authoritative before destructive cleanup.
  NAS_SECRET_TX_COMMITTED=true
  NAS_SECRET_TX_PHASE=committing
  if ! nas_secret_tx_privileged rm -rf -- "$NAS_SECRET_TX_PREVIOUS"; then
    NAS_SECRET_TX_PHASE=commit-cleanup-failed
    printf 'nas-secret-transaction: committed new tree but could not remove previous tree\n' >&2
    return 125
  fi
  if ! nas_secret_tx_remove_directory; then
    NAS_SECRET_TX_PHASE=commit-cleanup-failed
    printf 'nas-secret-transaction: committed new tree but could not remove transaction directory\n' >&2
    return 125
  fi
  NAS_SECRET_TX_PHASE=committed
}

nas_secret_tx_cleanup() {
  local rc=$1
  [[ "$rc" =~ ^[0-9]+$ && "$rc" -le 255 ]] || {
    printf 'nas-secret-transaction: cleanup status must be an exit status from 0 through 255\n' >&2
    return 125
  }
  if [[ "${NAS_SECRET_TX_COMMITTED:-false}" != true ]]; then
    # An uncommitted transaction is never a success, even if a caller accidentally
    # reaches EXIT with status 0. Restore the prior state and make the programming
    # error visible instead of leaving a swapped-but-uncommitted tree live.
    nas_secret_tx_rollback || return 125
    if [[ $rc -eq 0 ]]; then
      printf 'nas-secret-transaction: transaction exited successfully without commit; rolled back\n' >&2
      return 125
    fi
  fi
  return "$rc"
}
