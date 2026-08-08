#!/usr/bin/env bash
set -Eeuo pipefail

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
  nas-profile-local-ai
  nas-profile-all
)

checks=(
  nas-vm
  nas-vm-encrypted
)

for configuration in "${configurations[@]}"; do
  printf 'evaluating nixosConfigurations.%s\n' "$configuration"
  nix eval --raw ".#nixosConfigurations.${configuration}.config.system.build.toplevel.drvPath" >/dev/null
done

for check in "${checks[@]}"; do
  printf 'evaluating checks.x86_64-linux.%s\n' "$check"
  nix eval --raw ".#checks.x86_64-linux.${check}.drvPath" >/dev/null
done

printf 'reference configuration evaluation passed: %d configurations, %d checks\n' \
  "${#configurations[@]}" "${#checks[@]}"
