#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly FLAKE_REF="."
readonly PLACEHOLDER="nixosConfigurations.nas.config.system.build.toplevel.drvPath"
readonly -a CONFIGURATIONS=(
  nas-ci-ready
  nas-qemu
  nas-module-consumer
  nas-profile-core-storage
  nas-profile-identity-sharing
  nas-profile-observability
  nas-profile-virtualization
  nas-profile-local-ai
  nas-profile-all
)
readonly -a PLACEHOLDER_ERRORS=(
  "root file system"
  "boot.loader.grub.devices"
)
TEMPORARY_DIRECTORY=""

usage() {
  cat <<'USAGE'
Usage: scripts/nix-config-matrix.sh

Evaluate flake metadata, exported NixOS modules, every supported reference
configuration, and the intentionally invalid assertion fixtures. This command
instantiates derivations for evaluation but does not build their closures.
USAGE
}

die() {
  printf 'nix-config-matrix: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'nix-config-matrix: required command not found: %s\n' "$1" >&2
    exit 127
  }
}

cleanup() {
  [[ -z $TEMPORARY_DIRECTORY ]] || rm -rf -- "$TEMPORARY_DIRECTORY"
}

annotation_escape() {
  local value=$1
  value=${value//'%'/'%25'}
  value=${value//$'\r'/'%0D'}
  value=${value//$'\n'/'%0A'}
  printf '%s' "$value"
}

annotate_failure() {
  local title=$1 log=$2 detail
  detail="$(tail -c 6000 -- "$log" 2>/dev/null || true)"
  printf '::error file=scripts/nix-config-matrix.sh,line=1,title=%s::%s\n' \
    "$(annotation_escape "$title")" "$(annotation_escape "$detail")"
}

evaluate_flake_surface() {
  local log="$TEMPORARY_DIRECTORY/flake-surface.log"
  if ! nix flake metadata --json --no-write-lock-file "$FLAKE_REF" >"$log" 2>&1; then
    cat "$log" >&2
    annotate_failure "Nix flake metadata evaluation failed" "$log"
    return 1
  fi
  if ! nix eval --json --no-write-lock-file \
      "$FLAKE_REF#nixosModules" \
      --apply builtins.attrNames >"$log" 2>&1; then
    cat "$log" >&2
    annotate_failure "Nix module export evaluation failed" "$log"
    return 1
  fi
  printf 'Nix flake metadata and module exports evaluated successfully\n'
}

verify_placeholder_is_not_bootable() {
  local log=$1 expected

  if nix eval --raw --no-write-lock-file \
      "$FLAKE_REF#$PLACEHOLDER" >"$log" 2>&1; then
    printf '%s\n' "operator hardware placeholder unexpectedly evaluated as bootable" >>"$log"
    annotate_failure "Nix operator placeholder unexpectedly bootable" "$log"
    die "operator hardware placeholder unexpectedly evaluated as bootable"
  fi

  for expected in "${PLACEHOLDER_ERRORS[@]}"; do
    if ! grep -Fq -- "$expected" "$log"; then
      cat "$log" >&2
      annotate_failure "Nix operator placeholder failed for the wrong reason" "$log"
      die "operator hardware placeholder failed for the wrong reason; missing: $expected"
    fi
  done

  printf 'Nix operator hardware placeholder remains intentionally non-bootable\n'
}

evaluate_configuration() {
  local configuration=$1 drv_path log
  log="$TEMPORARY_DIRECTORY/$configuration.log"

  if ! drv_path="$(nix eval --raw --no-write-lock-file \
      "$FLAKE_REF#nixosConfigurations.$configuration.config.system.build.toplevel.drvPath" 2>"$log")"; then
    cat "$log" >&2
    annotate_failure "Nix configuration evaluation failed: $configuration" "$log"
    return 1
  fi
  [[ $drv_path == /nix/store/*.drv ]] || {
    printf '%s\n' "configuration $configuration returned an invalid derivation path: $drv_path" >"$log"
    annotate_failure "Nix configuration returned an invalid derivation: $configuration" "$log"
    die "configuration $configuration returned an invalid derivation path: $drv_path"
  }
  printf 'Nix configuration evaluation ok: %s (%s)\n' "$configuration" "$drv_path"
}

run_negative_matrix() {
  local log="$TEMPORARY_DIRECTORY/negative-matrix.log"
  if ! "$ROOT/scripts/nix-negative-tests.sh" >"$log" 2>&1; then
    cat "$log" >&2
    annotate_failure "Negative Nix configuration matrix failed" "$log"
    return 1
  fi
  cat "$log"
}

main() {
  if [[ ${1:-} == --help ]]; then
    usage
    exit 0
  fi
  (($# == 0)) || {
    printf 'Unexpected argument: %s\n' "$1" >&2
    exit 2
  }

  require_command nix
  require_command grep

  cd -- "$ROOT"
  TEMPORARY_DIRECTORY="$(mktemp -d)"
  trap cleanup EXIT

  evaluate_flake_surface
  verify_placeholder_is_not_bootable "$TEMPORARY_DIRECTORY/operator-placeholder.log"

  local configuration
  for configuration in "${CONFIGURATIONS[@]}"; do
    evaluate_configuration "$configuration"
  done

  run_negative_matrix
}

main "$@"