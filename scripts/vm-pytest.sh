#!/usr/bin/env bash
set -euo pipefail

# Run pytest inside the NixOS VM closure (the only place with /run/nas-state,
# nas-* system users, ZFS tank, and systemd units). Host `python -m pytest`
# is not a gate — see tests/README.md "Where tests run".
#
# Usage:
#   scripts/vm-pytest.sh -- jobs=4 pattern=test_coding_agent.py
#   scripts/vm-pytest.sh -- coverage
#   scripts/vm-pytest.sh -- --verbose tests/test_coding_agent.py

if ! command -v nix >/dev/null 2>&1; then
  echo "vm-pytest: nix is required (install via Determinate Nix or cachix)" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="vm"

# If --host is passed explicitly, run via nix develop (fast, still host, not VM)
if [[ "${1:-}" == "--host" ]]; then
  MODE="host"
  shift
fi

if [[ "$MODE" == "host" ]]; then
  exec nix develop "$ROOT#test" -c "$ROOT/scripts/run-unit-tests.py" "$@"
fi

# Default: full VM build. For quick iteration you can also:
#   nix develop .#test -c ./scripts/run-unit-tests.py --jobs 4
# but that still runs on host (no ZFS, no systemd). VM is the gate.

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if command -v qemu-system-x86_64 >/dev/null 2>&1 && [[ -f "$ROOT/tests/nixos/integration.nix" ]]; then
  echo "vm-pytest: building VM closure..." >&2
  nix build "$ROOT#checks.x86_64-linux.nas-vm" --show-trace -L 2>&1 | tail -n 20
  echo "vm-pytest: running pytest inside VM via qemu harness..." >&2
  # harness.sh expects repo at /tmp/nixos-nas-test inside VM; run-unit-tests there
  exec nix develop "$ROOT#qemu-test" -c "$ROOT/test/qemu/harness.sh" -- pytest "$@"
else
  echo "vm-pytest: qemu not available, falling back to nix develop host run (not VM-gated)" >&2
  echo "vm-pytest: for true VM gate, run: nix build .#checks.x86_64-linux.nas-vm --show-trace -L" >&2
  exec nix develop "$ROOT#test" -c "$ROOT/scripts/run-unit-tests.py" "$@"
fi
