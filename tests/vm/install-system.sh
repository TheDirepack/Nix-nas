#!/usr/bin/env bash
set -Eeuo pipefail

DISK="${NAS_INSTALL_DISK:-/dev/vda}"
ROOT_PARTITION="${DISK}1"
SOURCE="${NAS_INSTALL_SOURCE:-/mnt-source}"
TARGET="${NAS_INSTALL_TARGET:-/mnt}"
SSH_PUBLIC_KEY="${NAS_INSTALL_SSH_PUBLIC_KEY:-}"
FLAKE="${NAS_INSTALL_FLAKE:-nas-qemu}"

[[ -b "$DISK" ]] || { echo "Installer disk is missing: $DISK" >&2; exit 2; }
[[ -f "$SOURCE/flake.nix" ]] || { echo "NAS source flake is missing: $SOURCE" >&2; exit 2; }
[[ -f "$SSH_PUBLIC_KEY" ]] || { echo "Ephemeral SSH public key is missing: $SSH_PUBLIC_KEY" >&2; exit 2; }
[[ ! -L "$SSH_PUBLIC_KEY" ]] || { echo "Ephemeral SSH public key must not be a symlink" >&2; exit 2; }

swapoff -a || true
umount -R "$TARGET" 2>/dev/null || true
wipefs --all --force "$DISK"
parted --script "$DISK" \
  mklabel msdos \
  mkpart primary ext4 1MiB 100% \
  set 1 boot on
udevadm settle
mkfs.ext4 -F -L NIXOS_QEMU_ROOT "${DISK}1"
install -d -m 0755 "$TARGET"
mount -t ext4 "$ROOT_PARTITION" "$TARGET"

# The Open WebUI frontend can briefly exceed the installer VM's physical
# memory while Nix builds the complete appliance closure. Keep the full AI
# profile enabled and provide guest-local swap instead of reducing coverage.
swap_file="$TARGET/swapfile"
if [[ ! -e "$swap_file" ]]; then
  fallocate -l "${NAS_INSTALL_SWAP_GIB:-8}G" "$swap_file"
  chmod 0600 "$swap_file"
  mkswap "$swap_file" >/dev/null
fi
swapon "$swap_file" 2>/dev/null || true

export NIX_CONFIG="experimental-features = nix-command flakes"
nixos-install \
  --root "$TARGET" \
  --flake "path:$SOURCE#$FLAKE" \
  --no-root-passwd \
  --option accept-flake-config true \
  --option max-jobs 1 \
  --option cores 2 \
  --option warn-dirty false

# A second declarative install onto the mounted root must be non-destructive to
# unrelated persistent state. This catches install scripts that accidentally
# assume an empty filesystem after the partitioning stage.
install -d -m 0755 "$TARGET/var/lib/nas-install-test"
printf '%s\n' preserve-me > "$TARGET/var/lib/nas-install-test/reinstall-sentinel"
nixos-install \
  --root "$TARGET" \
  --flake "path:$SOURCE#$FLAKE" \
  --no-root-passwd \
  --option accept-flake-config true \
  --option max-jobs 1 \
  --option cores 2 \
  --option warn-dirty false
grep -qx preserve-me "$TARGET/var/lib/nas-install-test/reinstall-sentinel" || {
  echo "Repeated nixos-install destroyed unrelated persistent state" >&2
  exit 2
}

admin_home="$TARGET/home/admin"
[[ -d "$admin_home" ]] || { echo "Installed admin home is missing: $admin_home" >&2; exit 2; }
install -d -m 0700 "$admin_home/.ssh"
install -m 0600 "$SSH_PUBLIC_KEY" "$admin_home/.ssh/authorized_keys"
chown --reference="$admin_home" "$admin_home/.ssh" "$admin_home/.ssh/authorized_keys"

sync
echo "NIXOS_NAS_INSTALL_COMPLETE"
