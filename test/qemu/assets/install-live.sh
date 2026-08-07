#!/usr/bin/env bash
# install-live.sh — runs inside the NixOS live ISO (as root, over the serial
# console) and performs a fully unattended install to /dev/vda.
#
# The script and the installed configuration are delivered on a small
# read-only ext4 "provisioning" image (state/provisioning.img) attached as
# /dev/vdb; the serial driver mounts it at /provision and invokes this file.
set -euo pipefail

echo "=== nas-vm unattended install starting ==="
date

# --- wait for the SLIRP network to come up --------------------------------
for i in $(seq 1 30); do
  if ip -o -4 addr show 2>/dev/null | grep -q 'inet '; then
    break
  fi
  sleep 2
done
echo "--- network state ---"
ip -o -4 addr show || true
ip route || true

if ! getent hosts cache.nixos.org >/dev/null 2>&1; then
  echo "--- DNS lookup failed; forcing SLIRP DNS (10.0.2.3) ---"
  printf 'nameserver 10.0.2.3\n' > /etc/resolv.conf 2>/dev/null || true
fi
getent hosts cache.nixos.org || echo "WARN: still cannot resolve cache.nixos.org"

# --- partition /dev/vda (BIOS + GRUB on an MBR table) ----------------------
disk=/dev/vda
echo "--- partitioning $disk ---"
parted -s "$disk" mklabel msdos
parted -s "$disk" mkpart primary ext4 1MiB 100%
parted -s "$disk" set 1 boot on
partprobe "$disk" || true
sleep 1

echo "--- formatting /dev/vda1 ---"
mkfs.ext4 -F -q /dev/vda1

echo "--- mounting ---"
mount /dev/vda1 /mnt

echo "--- nixos-generate-config ---"
nixos-generate-config --root /mnt

echo "--- installing configuration.nix ---"
cp /provision/configuration.nix /mnt/etc/nixos/configuration.nix

echo "--- nixos-install (downloads + builds; this can take many minutes) ---"
nixos-install --no-root-passwd --root /mnt < /dev/null

echo "INSTALL_COMPLETE"
sync
sleep 1
poweroff
