#!/usr/bin/env bash
# harness.sh — convenience runner for the QEMU/NixOS test harness.
#
#   test/qemu/harness.sh install   unattended NixOS install into state/nas-vm.qcow2
#   test/qemu/harness.sh boot      boot the installed VM (background) + wait for SSH
#   test/qemu/harness.sh test      copy project into VM + flake eval smoke test
#   test/qemu/harness.sh ssh [..]  run a command in the VM (or a shell)
#   test/qemu/harness.sh stop      stop the VM
#   test/qemu/harness.sh status    is the VM running?
#   test/qemu/harness.sh keys      (re)generate + print the harness SSH key
#   test/qemu/harness.sh iso       interactive serial shell on the live ISO
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

cmd="${1:-help}"; shift || true
case "$cmd" in
  install)
    [ ! -f "$INSTALL_MARKER" ] || die "already installed (state/installed). Use: install.sh --force to redo"
    vm_running && die "VM is running (pid $(vm_pid)); run: harness.sh stop"
    "$QEMU_DIR/install.sh"
    ;;
  boot)
    [ -f "$INSTALL_MARKER" ] || die "not installed yet — run: harness.sh install"
    if vm_running; then
      log "VM already running (pid $(vm_pid))"
    else
      "$QEMU_DIR/run-vm.sh" --mode boot --background
      wait_for_ssh 300 || die "VM booted but SSH did not come up; see state/logs/vm-console.log"
    fi
    ;;
  test)
    "$QEMU_DIR/provision-project.sh"
    ;;
  ssh)
    exec ssh $SSH_ARGS root@127.0.0.1 "$@"
    ;;
  stop)
    if vm_running; then
      pid="$(vm_pid)"
      log "Stopping VM (pid $pid)"
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 20); do vm_running || break; sleep 1; done
      if vm_running; then kill -9 "$pid" 2>/dev/null || true; fi
      rm -f "$VM_PIDFILE" "$SERIAL_SOCK"
      log "Stopped."
    else
      log "VM not running."
    fi
    ;;
  status)
    if vm_running; then echo "running (pid $(vm_pid), ssh root@127.0.0.1:$SSH_PORT)"; else echo "stopped"; fi
    ;;
  keys)
    ensure_keys
    echo "private: $HARNESS_KEY"
    echo "public:  $HARNESS_KEY_PUB"
    ;;
  iso)
    vm_running && die "VM is running; stop it first"
    "$QEMU_DIR/run-vm.sh" --mode iso
    ;;
  help|-h|--help)
    sed -n '2,12p' "$0" | sed 's/^#   //; s/^#//'
    ;;
  *)
    echo "unknown command: $cmd" >&2
    sed -n '2,12p' "$0" | sed 's/^#   //; s/^#//' >&2
    exit 1
    ;;
esac
