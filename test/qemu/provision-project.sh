#!/usr/bin/env bash
# provision-project.sh — copy the project flake into the running VM and run a
# flake smoke test inside it (no nix on the host; all Nix work happens in the
# VM). Results are saved under test/qemu/state/logs/.
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

need_cmd rsync ssh

if [ ! -f "$INSTALL_MARKER" ]; then
  die "VM not installed yet — run: test/qemu/harness.sh install"
fi

if ! vm_running; then
  log "VM not running; booting the installed disk"
  "$QEMU_DIR/run-vm.sh" --mode boot --background
fi

wait_for_ssh 300 || die "VM did not become reachable over SSH"

log "Syncing project into VM:/root/nixos-nas (excluding test/qemu, .git, secrets)"
mkdir -p "$LOG_DIR"
rsync -az --delete \
  --exclude '.git/' \
  --exclude 'test/qemu/' \
  --exclude 'secrets/' \
  --exclude 'result' \
  --exclude 'result-*' \
  --exclude '.direnv/' \
  --exclude '.envrc' \
  -e "ssh $SSH_ARGS" \
  "$PROJECT_ROOT/" root@127.0.0.1:/root/nixos-nas/

log "Running flake smoke test inside the VM (fetching pinned inputs from GitHub; this may take a while)..."
set +e
ssh $SSH_ARGS root@127.0.0.1 '
  cd /root/nixos-nas
  echo "--- nix flake check --no-build ---"
  nix flake check --no-build > /tmp/flake-check.log 2>&1
  echo "flake_check_exit=$?"
  tail -n 25 /tmp/flake-check.log
  echo "--- nix eval .#nixosConfigurations.nas.config.nas.installationReady ---"
  nix eval .#nixosConfigurations.nas.config.nas.installationReady > /tmp/installationReady 2> /tmp/eval-err.log
  echo "eval_exit=$?"
  cat /tmp/installationReady 2>/dev/null
  cat /tmp/eval-err.log 2>/dev/null | tail -n 25
' 2>&1 | tee "$LOG_DIR/smoke-test.log"
ssh_rc=${PIPESTATUS[0]}
set -e

if [ "$ssh_rc" != 0 ]; then
  warn "Smoke test did not complete (ssh exit $ssh_rc). See $LOG_DIR/smoke-test.log"
  exit 1
fi

if grep -q '^eval_exit=0$' <(tr -d '\r' < "$LOG_DIR/smoke-test.log"); then
  log "Smoke test PASSED: flake evaluates and nas.installationReady is readable."
else
  warn "Flake eval did not return 0 — inspect $LOG_DIR/smoke-test.log"
  exit 1
fi

# `nix flake check` is expected to fail until the project is adapted for the
# VM: the placeholder hardware-configuration.nix sets no root fileSystem and
# no boot loader (nas.installationReady = false). Distinguish that expected
# failure from something new.
if grep -q '^flake_check_exit=0$' <(tr -d '\r' < "$LOG_DIR/smoke-test.log"); then
  log "nix flake check: PASSED (no build, all outputs evaluate)."
elif grep -qE "root file system|bootable" <(tr -d '\r' < "$LOG_DIR/smoke-test.log"); then
  log "nix flake check: FAILED as EXPECTED (placeholder hardware-config / installationReady=false)."
else
  warn "nix flake check failed for an unexpected reason — inspect $LOG_DIR/smoke-test.log"
fi
