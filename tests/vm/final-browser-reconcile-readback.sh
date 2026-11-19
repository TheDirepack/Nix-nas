#!/usr/bin/env bash
set -euo pipefail

control=/run/nas-control
unit=nas-managed-services-reconcile.service
history=(git --git-dir=/tank/nas-control/config-history.git)

desired_revision=$("${history[@]}" rev-parse --verify refs/heads/main)
applied_revision=$("${history[@]}" rev-parse --verify refs/nas/applied)
applied_hash=$("${history[@]}" show "$applied_revision:services.yaml" | sha256sum)
plan_revision=""
if [[ -r "$control/plan.json" ]]; then
  plan_revision=$(jq -r '.desiredRevision // ""' "$control/plan.json")
fi
document=$(nas-managed-services-control document | jq -ce '{
  name: .document.services["vm-oci-persist"].name,
  documentHash: .revision
}')
pending=false
if [[ -e "$control/reconcile.pending" ]]; then pending=true; fi
state=$(systemctl show "$unit" -p ActiveState -p Result -p InvocationID |
  jq -Rn '[inputs | capture("^(?<key>[^=]+)=(?<value>.*)$")] | from_entries')

jq -cn --arg time "$(date -u +%FT%T.%NZ)" --argjson state "$state" \
  --argjson document "$document" --argjson pending "$pending" \
  --arg desired "$desired_revision" --arg applied "$applied_revision" \
  --arg plan "$plan_revision" --arg appliedHash "${applied_hash%% *}" \
  '$document + $state + {time: $time, pending: $pending, desired: $desired,
    applied: $applied, plan: $plan, appliedHash: $appliedHash}'
