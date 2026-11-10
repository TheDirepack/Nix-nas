#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$ROOT"

if [[ ${1:-} == --help ]]; then
  cat <<'USAGE'
Usage: scripts/nix-negative-tests.sh

Evaluate intentionally invalid NAS configurations and require each one to fail
with its expected assertion, then require the paired valid fixtures (whose own
assertions check the generated configuration) to evaluate.
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
  'tests/nixos/invalid/installation-ready-empty-trusted-interfaces.nix|Set nas.trustedInterfaces to the actual LAN interface before installation.'
  'tests/nixos/invalid/installation-ready-zero-host-id.nix|networking.hostId must be a unique stable eight-hex-digit value.'
  'tests/nixos/invalid/installation-ready-no-recovery.nix|installationReady requires an administrator SSH key with OpenSSH enabled'
  'tests/nixos/invalid/installation-ready-ssh-group-denied.nix|installationReady requires an administrator SSH key with OpenSSH enabled'
  'tests/nixos/invalid/installation-ready-unencrypted.nix|ZFS encryption is disabled. Enable nas.zfsEncryption.enable or explicitly set nas.zfsEncryption.acknowledgeUnencrypted = true'
  'tests/nixos/invalid/backup-retired-remote.nix|Restic reads rclone and every other backend natively through'
  'tests/nixos/invalid/backup-retired-remote-scope.nix|It never limited what was backed up'
  'tests/nixos/invalid/backup-local-unacknowledged.nix|nas.backup.localRepository is local rollback storage, not an independent backup.'
  'tests/nixos/invalid/backup-renamed-rclone-config-without-repository.nix|nas.backup.rcloneConfigFile is used only for an rclone: repository named by nas.backup.repositoryFile.'
  'tests/nixos/invalid/update-probe-relative.nix|nas.update.externalProbeCommand must start with an absolute executable path'
  'tests/nixos/invalid/auto-update-apply-without-probe.nix|nas.autoUpdate.apply requires nas.update.externalProbeCommand'
)
valid_cases=(
  tests/nixos/valid/backup-repository-file.nix
  tests/nixos/valid/backup-local-rollback.nix
)

# AllowGroups/DenyGroups wildcard and negation cases are decided by pattern
# matching rather than by a single configuration, so evaluate them directly.
nix eval --impure --json --expr '
  import ./tests/nixos/install-readiness-eval.nix {
    lib = (builtins.getFlake (toString ./.)).inputs.nixpkgs.lib;
  }
'
nix eval --impure --json --expr '
  import ./tests/nixos/backup-policy-eval.nix {
    lib = (builtins.getFlake (toString ./.)).inputs.nixpkgs.lib;
  }
'

# The positive counterpart: a configured probe must reach the installed wrapper.
NAS_NEGATIVE_ROOT="$ROOT" nix eval --impure --json --file tests/nixos/update-probe-eval.nix
printf '\n'

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

for fixture in "${valid_cases[@]}"; do
  log="$(mktemp)"
  trap 'rm -f -- "$log"' EXIT
  if ! NAS_NEGATIVE_ROOT="$ROOT" NAS_NEGATIVE_FIXTURE="$fixture" \
      nix eval --impure --raw --file tests/nixos/negative-eval.nix >"$log" 2>&1; then
    cat "$log" >&2
    annotate_failure "Valid Nix fixture failed to evaluate: $fixture" "$log"
    exit 1
  fi
  rm -f -- "$log"
  trap - EXIT
  printf 'valid Nix fixture ok: %s\n' "$fixture"
done
