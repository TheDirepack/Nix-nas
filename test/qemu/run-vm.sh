#!/usr/bin/env bash
# run-vm.sh — boot the NixOS ISO (install) or the installed VM disk.
#
# Usage:
#   run-vm.sh                          # auto: boot installed disk if present, else ISO
#   run-vm.sh --mode boot              # boot the installed disk (QEMU BIOS + GRUB)
#   run-vm.sh --mode install           # boot the ISO live env for unattended install
#                                      #   (serial exposed on a unix socket)
#   run-vm.sh --mode iso               # boot the ISO live shell, interactive serial
#   run-vm.sh --background             # daemonize QEMU (writes state/vm.pid)
#   run-vm.sh --serial stdio|file|socket
#
# The ISO is booted by extracting its kernel + initrd + kernel command line
# (the serial-console isolinux entry) and passing them to QEMU directly with
# -kernel/-initrd/-append. This avoids interacting with the ISOLINUX/GRUB menu
# and gives the harness full control of the console. The ISO itself is still
# attached as a CD-ROM so stage-1 can mount it by volume label.
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

MODE=""
SERIAL=""
BACKGROUND=0
INSTALLED=0

[ -f "$INSTALL_MARKER" ] && INSTALLED=1

usage() {
  sed -n '2,12p' "$0" | sed 's/^# //; s/^#//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --serial) SERIAL="$2"; shift 2 ;;
    --background) BACKGROUND=1; shift ;;
    --foreground) BACKGROUND=0; shift ;;
    -h|--help) usage 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$MODE" ] || MODE=$([ "$INSTALLED" = 1 ] && echo boot || echo iso)

need_cmd "$QEMU_BIN" qemu-img 7z ssh-keygen
ensure_dirs
ensure_iso
ensure_keys
ensure_disk

# ---- extract kernel/initrd/cmdline from the ISO (cached) ------------------

iso_boot_files() {
  # Emits tagged lines for the serial-console entry (or the default entry with
  # console=ttyS0 appended, as a fallback for ISOs without a serial entry):
  #   K <kernel path>     I <initrd path>     A <kernel command line>
  local cfg="$1"
  local out
  out="$(awk '
    /^LABEL boot-serial$/ { inb=1; next }
    inb && /^LABEL/ { exit }
    inb && /^LINUX/ { print "K " $2 }
    inb && /^INITRD/ { print "I " $2 }
    inb && /^APPEND/ { sub(/^APPEND[ \t]+/, ""); print "A " $0 }
  ' "$cfg")"
  if [ -z "$out" ]; then
    out="$(awk '
      /^LABEL boot$/ { inb=1; next }
      inb && /^LABEL/ { exit }
      inb && /^LINUX/ { print "K " $2 }
      inb && /^INITRD/ { print "I " $2 }
      inb && /^APPEND/ { sub(/^APPEND[ \t]+/, ""); print "A " $0 " console=ttyS0,115200n8" }
    ' "$cfg")"
  fi
  printf '%s\n' "$out"
}

ensure_iso_boot_files() {
  local marker="$BOOT_DIR/.cache-marker"
  local iso_sig
  iso_sig="$(stat -c '%s-%Y' "$ISO")"
  if [ -f "$marker" ] && [ "$(cat "$marker")" = "$iso_sig" ] \
     && [ -s "$BOOT_DIR/bzImage" ] && [ -s "$BOOT_DIR/initrd" ] && [ -s "$BOOT_DIR/cmdline" ]; then
    return 0
  fi

  log "Extracting kernel/initrd/cmdline from ISO into state/boot ..."
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  7z x -y -o"$tmp" "$ISO" isolinux/isolinux.cfg >/dev/null 2>&1
  local cfg="$tmp/isolinux/isolinux.cfg"
  [ -f "$cfg" ] || die "could not extract isolinux.cfg from $ISO"

  local krel ired append
  while read -r tag value; do
    case "$tag" in
      K) krel="$value" ;;
      I) ired="$value" ;;
      A) append="$value" ;;
    esac
  done < <(iso_boot_files "$cfg")

  [ -n "${krel:-}" ] && [ -n "${ired:-}" ] || die "could not parse kernel/initrd paths from isolinux.cfg"

  # Normalise: strip leading slash, collapse double slashes.
  krel="$(printf '%s' "$krel" | sed -E 's#^/+##; s#/+#/#g')"
  ired="$(printf '%s' "$ired" | sed -E 's#^/+##; s#/+#/#g')"

  7z x -y -o"$tmp" "$ISO" "$krel" "$ired" >/dev/null 2>&1 || die "failed to extract kernel/initrd from ISO"

  local kf ifrd
  kf="$(find "$tmp" -type f -name bzImage | head -1)"
  ifrd="$(find "$tmp" -type f -name initrd | head -1)"
  [ -n "$kf" ] && [ -n "$ifrd" ] || die "extracted kernel/initrd not found"

  cp "$kf" "$BOOT_DIR/bzImage"
  cp "$ifrd" "$BOOT_DIR/initrd"
  printf '%s\n' "$append" > "$BOOT_DIR/cmdline"
  printf '%s\n' "$iso_sig" > "$marker"
  log "Using kernel cmdline: $append"
}

# ---- QEMU argument construction -------------------------------------------

common_args=(
  -enable-kvm
  -machine q35,accel=kvm
  -m "$VM_MEM"
  -smp "$VM_CPUS"
  -cpu host
  -name nas-vm
  -no-reboot
  -pidfile "$VM_PIDFILE"
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22
  -device virtio-net-pci,netdev=net0
  -device virtio-rng-pci
  -drive "file=$DISK,if=virtio,format=qcow2"
)

[ "$BACKGROUND" = 1 ] && common_args+=(-daemonize)

case "$MODE" in
  install)
    ensure_iso_boot_files
    rm -f "$SERIAL_SOCK"
    serial_args=(-serial "chardev:serial0" -chardev "socket,id=serial0,path=$SERIAL_SOCK,server=on,wait=off")
    common_args+=(
      -drive "file=$ISO,media=cdrom,readonly=on"
      -drive "file=$PROVISION_IMG,if=virtio,format=raw,readonly=on"
      -display none
      -monitor none
      "${serial_args[@]}"
      -kernel "$BOOT_DIR/bzImage"
      -initrd "$BOOT_DIR/initrd"
      -append "$(cat "$BOOT_DIR/cmdline")"
    )
    ;;
  iso)
    ensure_iso_boot_files
    common_args+=(
      -drive "file=$ISO,media=cdrom,readonly=on"
      -nographic
      -kernel "$BOOT_DIR/bzImage"
      -initrd "$BOOT_DIR/initrd"
      -append "$(cat "$BOOT_DIR/cmdline")"
    )
    ;;
  boot)
    [ "$INSTALLED" = 1 ] || die "no installed VM found (missing $INSTALL_MARKER); run: harness.sh install"
    case "$SERIAL" in
      stdio) serial_args=(-nographic) ;;
      *) serial_args=(-serial "file:$LOG_DIR/vm-console.log" -display none -monitor none) ;;
    esac
    if [ "$FIRMWARE" = "uefi" ]; then
      need_cmd cp
      [ -f "$OVMF_CODE" ] || die "OVMF firmware not found: $OVMF_CODE (set OVMF_CODE)"
      [ -f "$OVMF_VARS" ] || cp "$(dirname "$OVMF_CODE")/OVMF_VARS.4m.fd" "$OVMF_VARS"
      common_args+=(
        -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
        -drive "if=pflash,format=raw,file=$OVMF_VARS"
      )
    fi
    common_args+=("${serial_args[@]}")
    ;;
  *)
    die "unknown mode: $MODE (expected iso|install|boot)"
    ;;
esac

log "mode=$MODE firmware=$FIRMWARE mem=${VM_MEM}MiB cpus=$VM_CPUS ssh=127.0.0.1:$SSH_PORT"
exec "$QEMU_BIN" "${common_args[@]}"
