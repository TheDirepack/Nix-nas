#!/usr/bin/env bash
# install.sh — fully unattended NixOS install into test/qemu/state/nas-vm.qcow2
#
# Pipeline:
#   1. build a read-only ext4 "provisioning" image holding the install script
#      and the target configuration.nix (with the harness key baked in)
#   2. boot the live ISO (kernel+initrd+cmdline extracted from the ISO) with
#      QEMU -enable-kvm; attach the target qcow2 as /dev/vda and the
#      provisioning image as /dev/vdb
#   3. drive the login + install over the serial socket with serial-console.py
#   4. wait for the VM to power off and record state/installed
#
# Nothing here needs sudo: /dev/kvm is world-writable and QEMU runs as the
# current user.
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

need_cmd "$QEMU_BIN" qemu-img ssh-keygen truncate mkfs.ext4 python3 7z

if [ "$INSTALL_MARKER" ] && [ -f "$INSTALL_MARKER" ] && [ "$FORCE" != 1 ]; then
  die "already installed (state/installed exists). Delete it or run: install.sh --force"
fi
if vm_running; then
  die "a VM is already running (pid $(vm_pid)); run: test/qemu/harness.sh stop"
fi

ensure_dirs
ensure_iso
ensure_keys
ensure_disk

# --- build the provisioning image ------------------------------------------
log "Building provisioning image ($PROVISION_IMG)"
rm -rf "$PROVISION_DIR"
mkdir -p "$PROVISION_DIR"
cp "$QEMU_DIR/assets/install-live.sh" "$PROVISION_DIR/install-live.sh"
chmod +x "$PROVISION_DIR/install-live.sh"
python3 - "$HARNESS_KEY_PUB" "$QEMU_DIR/assets/configuration.nix" "$PROVISION_DIR/configuration.nix" <<'PY'
import sys
pub, src, dst = sys.argv[1:4]
key = open(pub).read().strip()
text = open(src).read().replace("__HARNESS_PUBLIC_KEY__", key)
open(dst, "w").write(text)
PY
cp "$HARNESS_KEY_PUB" "$PROVISION_DIR/harness-key.pub"
truncate -s 32M "$PROVISION_IMG"
mkfs.ext4 -q -F -d "$PROVISION_DIR" "$PROVISION_IMG"
qemu-img info "$PROVISION_IMG" | sed -n '1,3p'

# --- serial interaction plan ------------------------------------------------
cat > "$STATE_DIR/install.serial" <<'EOF'
loginroot
send:mkdir -p /provision && mount -r /dev/vdb /provision && bash /provision/install-live.sh
wait:INSTALL_COMPLETE
sleep:3
EOF

# --- launch QEMU (install mode, daemonized) ---------------------------------
log "Launching QEMU (install mode). Serial log: $LOG_DIR/install-console.log"
rm -f "$SERIAL_SOCK"
"$QEMU_DIR/run-vm.sh" --mode install --background

# --- drive the install ------------------------------------------------------
log "Driving the install over the serial console (this can take a long time)..."
set +e
python3 "$QEMU_DIR/serial-console.py" \
  --socket "$SERIAL_SOCK" \
  --script "$STATE_DIR/install.serial" \
  --log "$LOG_DIR/install-console.log" \
  --connect-timeout 120 \
  --boot-timeout 480 \
  --wait-timeout 2400
rc=$?
set -e

if [ "$rc" != 0 ]; then
  warn "Serial driver failed (exit $rc)."
  warn "Full console captured in $LOG_DIR/install-console.log"
  if vm_running; then
    warn "Killing VM."
    "$QEMU_DIR/harness.sh" stop || true
  fi
  exit 1
fi

# --- wait for the VM to power off, then record success -----------------------
log "Install marker observed; waiting for the VM to power off"
deadline=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  vm_running || break
  sleep 2
done
if vm_running; then
  warn "VM did not power off cleanly; forcing stop"
  "$QEMU_DIR/harness.sh" stop || true
fi

date > "$INSTALL_MARKER"
qemu-img info "$DISK" | sed -n '1,5p'
log "Install complete."
log "Next: test/qemu/harness.sh boot   (boots the installed VM + waits for SSH)"
log "      test/qemu/harness.sh test   (copies the project + flake smoke test)"
