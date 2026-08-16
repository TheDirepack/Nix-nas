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

Evaluate flake metadata and exported NixOS modules, verify the operator hardware
placeholder remains intentionally non-bootable, and run the intentionally invalid
assertion fixtures. Complete supported reference configurations and VM check
outputs are evaluated once by scripts/evaluate-reference-configurations.sh.
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

evaluate_flake_surface() {
  nix flake metadata --json --no-write-lock-file "$FLAKE_REF" >/dev/null
  nix eval --json --no-write-lock-file \
    "$FLAKE_REF#nixosModules" \
    --apply builtins.attrNames >/dev/null
  printf 'Nix flake metadata and module exports evaluated successfully\n'
}

verify_reference_evaluator_ownership() {
  local configuration evaluator="$ROOT/scripts/evaluate-reference-configurations.sh"
  for configuration in "${CONFIGURATIONS[@]}"; do
    grep -Fq -- "$configuration" "$evaluator" || \
      die "reference evaluator does not own supported configuration: $configuration"
  done
  printf 'Reference configuration evaluation is delegated to the dedicated evaluator\n'
}

verify_placeholder_is_not_bootable() {
  local log=$1 expected

  if nix eval --raw --no-write-lock-file \
      "$FLAKE_REF#$PLACEHOLDER" >"$log" 2>&1; then
    die "operator hardware placeholder unexpectedly evaluated as bootable"
  fi

  for expected in "${PLACEHOLDER_ERRORS[@]}"; do
    if ! grep -Fq -- "$expected" "$log"; then
      cat "$log" >&2
      die "operator hardware placeholder failed for the wrong reason; missing: $expected"
    fi
  done

  printf 'Nix operator hardware placeholder remains intentionally non-bootable\n'
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
  verify_reference_evaluator_ownership
  verify_placeholder_is_not_bootable "$TEMPORARY_DIRECTORY/operator-placeholder.log"
  "$ROOT/scripts/nix-negative-tests.sh"
}

main "$@"
