#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$ROOT"

if [[ ${1:-} == --help ]]; then
  cat <<'USAGE'
Usage: scripts/nix-negative-tests.sh

Evaluate intentionally invalid NAS configurations and require each one to fail
with its expected assertion. This is a negative test: successful evaluation is
a test failure.
USAGE
  exit 0
fi
if (($#)); then
  printf 'Unexpected argument: %s\n' "$1" >&2
  exit 2
fi
command -v nix >/dev/null 2>&1 || { echo 'nix is required' >&2; exit 127; }

annotation_escape() {
  local value=$1
  value=${value//'%'/'%25'}
  value=${value//$'\r'/'%0D'}
  value=${value//$'\n'/'%0A'}
  printf '%s' "$value"
}

annotate_failure() {
  local title=$1 log=$2 head tail detail
  head="$(head -c 3000 -- "$log" 2>/dev/null || true)"
  tail="$(tail -c 3000 -- "$log" 2>/dev/null || true)"
  detail="$head"
  if [[ $tail != "$head" ]]; then
    detail+=$'\n... trace tail ...\n'
    detail+="$tail"
  fi
  printf '::error file=scripts/nix-negative-tests.sh,line=1,title=%s::%s\n' \
    "$(annotation_escape "$title")" "$(annotation_escape "$detail")"
}

cases=(
  'tests/nixos/invalid/trusted-loopback.nix|nas.trustedInterfaces must contain real non-loopback interface names.'
  'tests/nixos/invalid/trusted-duplicate.nix|nas.trustedInterfaces must not contain duplicate interface names.'
  'tests/nixos/invalid/zfs-dataset-root.nix|nas.zfsDataset must be a child dataset of nas.zfsPool'
  'tests/nixos/invalid/tftp-privileged-port.nix|nas.tftp.internalPort must be unprivileged'
  'tests/nixos/invalid/replication-same-dataset.nix|nas.zfsReplication.enable requires a non-empty destination'
  'tests/nixos/invalid/firewall-without-networking.nix|nas.networking.firewall.enable requires nas.networking.enable.'
)

for row in "${cases[@]}"; do
  fixture=${row%%|*}
  expected=${row#*|}
  log="$(mktemp)"
  trap 'rm -f -- "$log"' EXIT
  if NAS_NEGATIVE_ROOT="$ROOT" NAS_NEGATIVE_FIXTURE="$fixture" \
      nix eval --impure --raw --file tests/nixos/negative-eval.nix >"$log" 2>&1; then
    cat "$log" >&2
    printf '%s\n' "negative Nix fixture unexpectedly evaluated: $fixture" >>"$log"
    annotate_failure "Negative Nix fixture unexpectedly valid: $fixture" "$log"
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$log"; then
    cat "$log" >&2
    printf '%s\n' "expected assertion: $expected" >>"$log"
    annotate_failure "Negative Nix fixture failed for wrong reason: $fixture" "$log"
    echo "negative Nix fixture failed for the wrong reason: $fixture" >&2
    exit 1
  fi
  rm -f -- "$log"
  trap - EXIT
  printf 'negative Nix assertion ok: %s\n' "$fixture"
done
