#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  local status=$1
  shift
  printf 'evaluate-reference-configurations: %s\n' "$*" >&2
  exit "$status"
}

# Preserve nix's own exit status so CI surfaces the real evaluation failure code
# instead of collapsing every failure into a generic 1.
nix_eval() {
  local attribute=$1
  local description=$2
  local status=0
  nix eval --raw "$attribute" >/dev/null || status=$?
  if ((status != 0)); then
    fail "$status" "nix eval failed for ${description}"
  fi
}

# The repository's nixosConfigurations.nas intentionally imports the checked-in
# hardware-configuration.nix placeholder.  That output becomes bootable only
# after an administrator replaces the placeholder with nixos-generate-config
# output for the target machine.  CI must not make that placeholder bootable by
# inventing a root filesystem or bootloader device.
#
# Instead, evaluate every complete reference/consumer configuration plus the
# NixOS VM checks.  These exercise the same modules with explicit test hardware
# and therefore catch module evaluation/assertion regressions without creating
# unsafe production defaults.

configurations=(
  nas-ci-ready
  nas-qemu
  nas-module-consumer
  nas-profile-core-storage
  nas-profile-identity-sharing
  nas-profile-observability
  nas-profile-virtualization
  nas-profile-all
)

checks=(
  nas-vm
  nas-vm-encrypted
)

for configuration in "${configurations[@]}"; do
  printf 'evaluating nixosConfigurations.%s\n' "$configuration"
  nix_eval ".#nixosConfigurations.${configuration}.config.system.build.toplevel.drvPath" \
    "nixosConfigurations.${configuration}"
done

for check in "${checks[@]}"; do
  printf 'evaluating checks.x86_64-linux.%s\n' "$check"
  nix_eval ".#checks.x86_64-linux.${check}.drvPath" "checks.x86_64-linux.${check}"
done

printf 'reference configuration evaluation passed: %d configurations, %d checks\n' \
  "${#configurations[@]}" "${#checks[@]}"
