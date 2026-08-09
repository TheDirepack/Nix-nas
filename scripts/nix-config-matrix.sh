#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$ROOT"

if [[ ${1:-} == --help ]]; then
  cat <<'USAGE'
Usage: scripts/nix-config-matrix.sh

Evaluate flake metadata, the appliance/reusable profile matrix, and the
intentionally-invalid assertion fixtures. No closures are built.
USAGE
  exit 0
fi
if (($#)); then
  printf 'Unexpected argument: %s\n' "$1" >&2
  exit 2
fi
command -v nix >/dev/null 2>&1 || { echo 'nix is required' >&2; exit 127; }

nix flake metadata --json >/dev/null
nix eval --json .#nixosModules --apply 'modules: builtins.attrNames modules' >/dev/null

placeholder_log="$(mktemp)"
trap 'rm -f -- "$placeholder_log"' EXIT
if nix eval --raw .#nixosConfigurations.nas.config.system.build.toplevel.drvPath 2>"$placeholder_log"; then
  echo "Operator hardware placeholder unexpectedly evaluated as bootable" >&2
  exit 1
fi
for expected in "root file system" "boot.loader.grub.devices"; do
  grep -Fq "$expected" "$placeholder_log" || {
    cat "$placeholder_log" >&2
    echo "Operator hardware placeholder failed for the wrong reason; missing: $expected" >&2
    exit 1
  }
done
printf 'Nix operator hardware placeholder remains intentionally non-bootable\n'

for configuration in \
  nas-ci-ready nas-qemu nas-module-consumer \
  nas-profile-core-storage nas-profile-identity-sharing \
  nas-profile-observability nas-profile-virtualization \
  nas-profile-local-ai nas-profile-all; do
  nix eval --raw ".#nixosConfigurations.${configuration}.config.system.build.toplevel.drvPath"
  printf 'Nix configuration evaluation ok: %s\n' "$configuration"
done
./scripts/nix-negative-tests.sh
