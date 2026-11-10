#!/usr/bin/env bash
set -Eeuo pipefail

original_args=("$@")

apply=false
sync=false
non_interactive=false
allow_inactive_protected_stack=false
status_only=false
json_output=false
allow_local_health_only=false

usage() {
  cat <<'USAGE'
Usage: nas-update [OPTIONS]

Validate and optionally deploy the reviewed flake revision in NAS_CONFIG_DIR.
With --sync it fast-forwards to the configured upstream branch. It never edits
flake inputs or dependency pins itself; Renovate and CI own those changes.

Options:
  --sync        Fetch the configured Git upstream and fast-forward only.
                The fetched revision is still fully evaluated and built.
  --apply       Test, health-check, and switch to the reviewed generation.
  --non-interactive
                Do not prompt before activation.
  --allow-inactive-protected-stack
                Permit --apply while KeePassXC-gated services are stopped.
  --allow-local-health-only
                Advanced recovery override: persist after local-only health checks.
                Normal deployment requires NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON,
                which the installed command sets from nas.update.externalProbeCommand.
  --status      Inspect the protected configuration checkout without building.
  --json        Emit machine-readable status; valid only with --status.
  -h, --help    Show this help.
USAGE
}

while (($#)); do
  case "$1" in
    --sync) sync=true ;;
    --apply) apply=true ;;
    --non-interactive) non_interactive=true ;;
    --allow-inactive-protected-stack) allow_inactive_protected_stack=true ;;
    --allow-local-health-only) allow_local_health_only=true ;;
    --status) status_only=true ;;
    --json) json_output=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

$json_output && ! $status_only && { echo "--json requires --status." >&2; exit 2; }
(( EUID == 0 )) || { echo "Run nas-update as root." >&2; exit 1; }
if ! $status_only; then
  operation_runner="${NAS_OPERATION_RUNNER:-/run/current-system/sw/bin/nas-operation-run}"
  [[ -x "$operation_runner" ]] || {
    echo "NAS operation coordinator is unavailable: $operation_runner" >&2
    exit 1
  }
  operation_class=update
  if $apply || $sync; then
    operation_class=appliance
  fi
  if [[ -n "${NAS_OPERATION_COORDINATION_TOKEN:-}" ]]; then
    "$operation_runner" --validate-current --class "$operation_class" || exit $?
  else
    exec "$operation_runner" --action nas-update --class "$operation_class" -- "$0" "${original_args[@]}"
  fi
fi
config_dir="${NAS_CONFIG_DIR:-/etc/nixos/nixos-nas}"
cd "$config_dir"
config_dir="$(pwd -P)"
active_config_dir="$config_dir"
deployment_dir="$config_dir"
candidate_worktree=""
candidate_root=""
candidate_commit=""
source_promoted=false
original_source_commit=""
authentik_port="${NAS_AUTHENTIK_PORT:-9000}"
authentik_path="${NAS_AUTHENTIK_PATH:-/identity/}"
caddy_ca_file="${NAS_CADDY_CA_FILE:-/run/nas-caddy-ca/ca-bundle.crt}"
firewall_enabled="${NAS_FIREWALL_ENABLED:-1}"
firewall_zone="${NAS_FIREWALL_ZONE:-nas-lan}"
lan_host="${NAS_LAN_HOST:-$(cat /proc/sys/kernel/hostname).local}"
trusted_interfaces="${NAS_TRUSTED_INTERFACES:-}"
v2_systemd_state="${NAS_V2_SYSTEMD_STATE:-/run/nas-control/systemd-reconciled.json}"
v2_reconcile_pending="${NAS_V2_RECONCILE_PENDING:-/run/nas-control/reconcile.pending}"
copyparty_expected=false
application_settle_seconds="${NAS_UPDATE_APPLICATION_SETTLE_SECONDS:-300}"
if ! [[ "$application_settle_seconds" =~ ^[0-9]+$ ]] || ((10#$application_settle_seconds < 1 || 10#$application_settle_seconds > 3600)); then
  echo "NAS_UPDATE_APPLICATION_SETTLE_SECONDS must be an integer between 1 and 3600." >&2
  exit 2
fi
application_settle_seconds=$((10#$application_settle_seconds))
copyparty_socket=/run/copyparty/http.sock
cockpit_socket=/run/nas-cockpit-sso/ws.sock

require_commands() {
  local command
  for command in "$@"; do
    command -v "$command" >/dev/null 2>&1 || { echo "Missing command: $command" >&2; exit 1; }
  done
}

require_commands readlink git jq

export HOME=/var/empty
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_OPTIONAL_LOCKS=0

git_safe() {
  git -c core.hooksPath=/dev/null "$@"
}

cleanup_candidate() {
  if [[ -n "$candidate_worktree" ]]; then
    git_safe -C "$active_config_dir" worktree remove --force "$candidate_worktree" >/dev/null 2>&1 || rm -rf "$candidate_worktree"
    candidate_worktree=""
  fi
  if [[ -n "$candidate_root" ]]; then
    rm -rf -- "$candidate_root"
    candidate_root=""
  fi
}
trap cleanup_candidate EXIT

listener_present() {
  local port=$1
  ss -ltnH | awk -v expected=":$port" '$4 ~ expected "$" { found=1 } END { exit !found }'
}

management_route_reachable() {
  [[ -r "$caddy_ca_file" ]] || { echo "Caddy CA export is unavailable at $caddy_ca_file" >&2; return 1; }
  local status
  status="$(curl --silent --show-error --max-time 10 \
    --cacert "$caddy_ca_file" \
    --resolve "$lan_host:443:127.0.0.1" \
    --output /dev/null --write-out '%{http_code}' \
    "https://$lan_host/")"
  [[ "$status" =~ ^[1-4][0-9][0-9]$ ]] || {
    echo "Caddy management route returned HTTP $status" >&2
    return 1
  }
}

external_management_probe() {
  local raw="${NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON:-}"
  local validate_only=false
  [[ "${1:-}" == "--validate" ]] && validate_only=true
  if [[ -z "$raw" ]]; then
    $allow_local_health_only && {
      echo "WARNING: persisting after local-only management checks by explicit override." >&2
      return 0
    }
    echo "Persistent deployment requires NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON (nas.update.externalProbeCommand) from an independent management path, or --allow-local-health-only for recovery." >&2
    return 1
  fi
  local -a probe=()
  local decoder_output decoder_pid decoder_status=0
  # The decoder cannot be read from a pipeline or process substitution: both
  # discard its exit status, and only bash >= 5.3 records a substitution's pid
  # in $!. A background job keeps a portable pid and a file keeps the NUL
  # separated argv, so a failing decoder is always observed before any launch.
  decoder_output="$(mktemp "${TMPDIR:-/tmp}/nas-probe-argv.XXXXXX")" || return 1
  python3 - "$raw" >"$decoder_output" <<'PY_EXTERNAL_PROBE' &
import json
import sys

try:
    value = json.loads(sys.argv[1])
except (json.JSONDecodeError, RecursionError):
    raise SystemExit("external probe command must be valid JSON")
if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
    raise SystemExit("external probe command must be a nonempty JSON string array")
encoded = []
for item in value:
    if "\x00" in item:
        raise SystemExit("external probe argument contains NUL")
    try:
        encoded.append(item.encode())
    except UnicodeEncodeError:
        raise SystemExit("external probe argument must be UTF-8 encodable") from None
sys.stdout.buffer.write(b"\0".join(encoded) + b"\0")
PY_EXTERNAL_PROBE
  decoder_pid=$!
  wait "$decoder_pid" || decoder_status=$?
  if ((decoder_status != 0)); then
    rm -f -- "$decoder_output"
    return "$decoder_status"
  fi
  mapfile -d '' -t probe <"$decoder_output" || decoder_status=$?
  rm -f -- "$decoder_output"
  ((decoder_status == 0)) || return "$decoder_status"
  ((${#probe[@]})) || {
    echo "External management probe command is empty." >&2
    return 1
  }
  [[ "${probe[0]}" == /* && -f "${probe[0]}" && -x "${probe[0]}" ]] || {
    echo "External management probe executable is not an absolute executable file: ${probe[0]}" >&2
    return 1
  }
  $validate_only && return 0
  timeout 60 "${probe[@]}"
}

# V2 owns application lifecycle. The reconciler's committed start set names the
# exact native units it expects to run, so modes such as "off" are honored
# without re-encoding application policy here. Readiness gates are oneshot
# units that are inactive once passed; they are listed separately and only
# must not be failed. Every command reports its own failure: callers also use
# these functions in conditional context.
v2_expected_units() {
  [[ -f "$v2_systemd_state" && -r "$v2_systemd_state" ]] || {
    echo "Managed Services V2 start state is unavailable at $v2_systemd_state; refusing to guess which applications must run." >&2
    return 1
  }
  jq -r '
    # Same unit-name contract as nas_v2_systemd_reconcile; callers pass units after "--".
    def unit_name: type == "string" and test("\\A[A-Za-z0-9_.@:-]+[.](service|socket|timer|path|target)\\z");
    if type == "object" and .schemaVersion == 1 and (.startUnits | type) == "array" and all(.startUnits[]; unit_name)
      and ((.readinessUnits // []) | type) == "array" and all((.readinessUnits // [])[]; unit_name)
    then (.readinessUnits // []) as $gates
      | .startUnits[] | if IN($gates[]) then "gate " + . else "run " + . end
    else error("schemaVersion must be 1 and startUnits and readinessUnits must be arrays of unit names")
    end' "$v2_systemd_state" || {
    echo "Managed Services V2 start state at $v2_systemd_state is invalid." >&2
    return 1
  }
}

# Classifies V2 units without waiting. With --wait it polls until every running
# unit is active and every gate has finished, up to the settle deadline: units
# that recovery started with --no-block may still be activating. Sets
# copyparty_expected for application_health.
application_units_active() {
  local wait=false listing entry kind unit state deadline
  local -a expected=() pending=() next=() unsettled=() failed=()
  [[ "${1:-}" == --wait ]] && wait=true
  copyparty_expected=false
  deadline=$((SECONDS + application_settle_seconds))
  if $wait; then
    until managed_services_settled 2>/dev/null; do
      ((SECONDS < deadline)) || { managed_services_settled; return 1; }
      sleep 2
    done
  fi
  listing="$(v2_expected_units)" || return 1
  [[ -z "$listing" ]] || mapfile -t expected <<<"$listing"
  for entry in "${expected[@]}"; do
    [[ "$entry" == "run copyparty.service" ]] && copyparty_expected=true
  done
  pending=("${expected[@]}")
  while :; do
    next=()
    unsettled=()
    for entry in "${pending[@]}"; do
      kind="${entry%% *}"
      unit="${entry#* }"
      state="$(systemctl is-active -- "$unit" 2>/dev/null || true)"
      case "$kind:$state" in
        run:active | gate:active | gate:inactive) ;;
        *:failed) failed+=("$unit") ;;
        *)
          next+=("$entry")
          unsettled+=("$unit (${state:-unknown})")
          ;;
      esac
    done
    if ((${#failed[@]})); then
      echo "Managed Services V2 units failed: ${failed[*]}" >&2
      return 1
    fi
    ((${#unsettled[@]})) || return 0
    if ! $wait; then
      echo "Managed Services V2 expects these units to run, but they are not active: ${unsettled[*]}" >&2
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "Managed Services V2 units did not become active within ${application_settle_seconds}s: ${unsettled[*]}" >&2
      return 1
    fi
    pending=("${next[@]}")
    sleep 2
  done
}

# A pending or running reconcile can still stop units or replace the start set.
managed_services_settled() {
  local state
  state="$(systemctl is-active nas-managed-services-reconcile.service 2>/dev/null || true)"
  if [[ -e "$v2_reconcile_pending" || "$state" =~ ^(active|activating|deactivating|reloading)$ ]]; then
    echo "Managed Services reconciliation is pending or running; retry after it settles, or inspect nas-managed-services-reconcile.service." >&2
    return 1
  fi
}

application_health() {
  application_units_active "$@" || return 1
  if $copyparty_expected; then
    [[ -S "$copyparty_socket" ]] || { echo "CopyParty Unix listener is missing" >&2; return 1; }
    curl --fail --silent --show-error --max-time 10 --unix-socket "$copyparty_socket" http://localhost/ >/dev/null || {
      echo "CopyParty did not answer on its Unix listener" >&2
      return 1
    }
  fi
}

health_check() {
  systemctl is-active --quiet sshd.service
  zpool status -x >/dev/null
  zfs list >/dev/null

  local interface current_zone
  for interface in $trusted_interfaces; do
    ip link show "$interface" >/dev/null
    ip -o address show dev "$interface" scope global | grep -q . || {
      echo "Trusted interface $interface has no global address" >&2
      return 1
    }
    ip route show dev "$interface" | grep -q . || {
      echo "Trusted interface $interface has no route" >&2
      return 1
    }
    if [[ "$firewall_enabled" == "1" ]]; then
      current_zone="$(firewall-cmd --get-zone-of-interface="$interface")"
      [[ "$current_zone" == "$firewall_zone" ]] || {
        echo "Trusted interface $interface is in $current_zone instead of $firewall_zone" >&2
        return 1
      }
    fi
  done

  listener_present 22 || { echo "sshd is not listening" >&2; return 1; }
  if $protected_was_active; then
    for unit in postgresql.service authentik-worker.service authentik.service nas-cockpit-sso.socket nas-cockpit-sso.service caddy.service; do
      systemctl is-active --quiet "$unit" || { echo "$unit is not active" >&2; return 1; }
    done
    application_health --wait || return 1
    [[ -S "$cockpit_socket" ]] || { echo "Cockpit Unix listener is missing" >&2; return 1; }
    listener_present 443 || { echo "Caddy is not listening on 443" >&2; return 1; }
    curl --fail --silent --show-error --max-time 10 "http://127.0.0.1:${authentik_port}${authentik_path}-/health/ready/" >/dev/null
    curl --fail --silent --show-error --max-time 10 --unix-socket "$cockpit_socket" http://localhost/console/ >/dev/null
    management_route_reachable
  fi
}

inside_git=false
if git_safe rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  inside_git=true
fi

if $status_only; then
  revision=unknown
  branch=unknown
  upstream=''
  dirty=null
  ahead=null
  behind=null
  if $inside_git; then
    revision="$(git_safe rev-parse --short=12 HEAD 2>/dev/null || printf unknown)"
    branch="$(git_safe branch --show-current 2>/dev/null || printf unknown)"
    [[ -n "$branch" ]] || branch=detached
    if [[ -n "$(git_safe status --porcelain --untracked-files=normal)" ]]; then dirty=true; else dirty=false; fi
    upstream="$(git_safe rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
    if [[ -n "$upstream" ]]; then
      counts="$(git_safe rev-list --left-right --count "HEAD...$upstream" 2>/dev/null || true)"
      if [[ "$counts" =~ ^([0-9]+)[[:space:]]+([0-9]+)$ ]]; then
        ahead="${BASH_REMATCH[1]}"
        behind="${BASH_REMATCH[2]}"
      fi
    fi
  fi
  current_system="$(readlink -f /run/current-system 2>/dev/null || true)"
  # Report the admission checks --apply performs, without launching the probe
  # or contacting applications, so clients can explain why persistent
  # deployment is unavailable. Recovery overrides are deliberately ignored.
  apply_blockers='[]'
  add_apply_blocker() {
    apply_blockers="$(jq -c --arg code "$1" --arg message "$2" '. + [{code:$code, message:$message}]' <<<"$apply_blockers")"
  }
  probe_configured=false
  probe_valid=null
  probe_error=''
  if [[ -n "${NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON:-}" ]]; then
    probe_configured=true
    if probe_error="$(external_management_probe --validate 2>&1 >/dev/null)"; then
      probe_valid=true
    else
      probe_valid=false
      [[ -n "$probe_error" ]] || probe_error="external probe command is invalid"
      add_apply_blocker external-probe-invalid "The configured independent management probe is invalid: $probe_error"
    fi
  else
    add_apply_blocker external-probe-unconfigured \
      "Applying an update requires an independent management probe. Set nas.update.externalProbeCommand in the NixOS configuration."
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    add_apply_blocker runtime-state-unavailable "systemctl is unavailable, so protected-service state cannot be inspected."
  elif ! systemctl is-active --quiet nas-protected-services.target; then
    add_apply_blocker protected-services-stopped \
      "Protected services are stopped. Unlock KeePassXC and activate secrets before applying an update."
  elif ! runtime_detail="$(managed_services_settled 2>&1 >/dev/null)"; then
    add_apply_blocker managed-services-reconciling "$runtime_detail"
  elif ! runtime_detail="$(application_units_active 2>&1 >/dev/null)"; then
    add_apply_blocker applications-unhealthy \
      "$runtime_detail. Repair them or turn their applications off in Managed Services first."
  fi
  if $json_output; then
    jq -n \
      --arg configurationDir "$config_dir" \
      --arg revision "$revision" \
      --arg branch "$branch" \
      --arg upstream "$upstream" \
      --arg currentSystem "$current_system" \
      --arg probeError "$probe_error" \
      --argjson git "$inside_git" \
      --argjson dirty "$dirty" \
      --argjson ahead "$ahead" \
      --argjson behind "$behind" \
      --argjson probeConfigured "$probe_configured" \
      --argjson probeValid "$probe_valid" \
      --argjson applyBlockers "$apply_blockers" \
      '{configurationDir:$configurationDir, git:$git, revision:$revision, branch:$branch, upstream:(if $upstream == "" then null else $upstream end), ahead:$ahead, behind:$behind, dirty:$dirty, currentSystem:$currentSystem,
        externalProbe:{configured:$probeConfigured, valid:$probeValid, error:(if $probeError == "" then null else $probeError end)},
        applyBlockers:$applyBlockers}'
  else
    if ! $probe_configured; then
      probe_summary="not configured"
    elif [[ "$probe_valid" == true ]]; then
      probe_summary=configured
    else
      probe_summary="invalid: $probe_error"
    fi
    apply_summary="$(jq -r 'if length == 0 then "no known blockers" else "unavailable: " + (map(.message) | join(" ")) end' <<<"$apply_blockers")"
    printf 'Configuration: %s\nRevision: %s\nBranch: %s\nUpstream: %s\nDirty: %s\nCurrent system: %s\nExternal probe: %s\nApply: %s\n' \
      "$config_dir" "$revision" "$branch" "${upstream:-none}" "$dirty" "$current_system" "$probe_summary" "$apply_summary"
  fi
  exit 0
fi

require_commands nix nixos-rebuild systemctl zfs zpool curl sha256sum ip ss firewall-cmd

if $inside_git; then
  [[ -z "$(git_safe status --porcelain --untracked-files=normal)" ]] || {
    echo "Refusing to deploy a dirty Git working tree." >&2
    exit 1
  }
  original_source_commit="$(git_safe rev-parse HEAD)"
fi

if $sync; then
  $inside_git || { echo "--sync requires a Git checkout." >&2; exit 1; }
  upstream="$(git_safe rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)" || {
    echo "The current branch has no configured upstream." >&2
    exit 1
  }
  remote="${upstream%%/*}"
  branch="${upstream#*/}"
  [[ -n "$remote" && -n "$branch" && "$remote" != "$upstream" ]] || {
    echo "Unable to resolve the configured Git upstream: $upstream" >&2
    exit 1
  }
  echo "Fetching approved updates from $upstream without advancing the active checkout..."
  git_safe fetch --prune "$remote" "$branch"
  candidate_commit="$(git_safe rev-parse FETCH_HEAD)"
  git_safe merge-base --is-ancestor HEAD "$candidate_commit" || {
    echo "Approved update is not a fast-forward descendant of the active revision." >&2
    exit 1
  }
  candidate_root="$(mktemp -d /var/tmp/nas-update-candidate.XXXXXX)"
  candidate_worktree="$candidate_root/source"
  git_safe worktree add --detach "$candidate_worktree" "$candidate_commit" >/dev/null
  deployment_dir="$candidate_worktree"
fi

cd "$deployment_dir"
flake_ref="$deployment_dir#${NAS_NIXOS_CONFIGURATION:-nas}"
if ! $inside_git && [[ -f MANIFEST.sha256 ]]; then
  sha256sum --check MANIFEST.sha256
fi

protected_was_active=false
if systemctl is-active --quiet nas-protected-services.target; then
  protected_was_active=true
fi
if $apply && ! $protected_was_active && ! $allow_inactive_protected_stack; then
  echo "Protected services are stopped. Unlock KeePassXC and run nas-secrets activate, or pass --allow-inactive-protected-stack." >&2
  exit 1
fi

if $apply && ! $non_interactive; then
  read -r -p "Build and deploy the reviewed candidate at $deployment_dir? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || exit 0
fi

restart_protected() {
  $protected_was_active || return 0
  systemctl restart nas-protected-services.target
}

update_state_root=/var/lib/nas-update
state_snapshot=""
manual_recovery_marker="$update_state_root/manual-recovery-required.json"
state_snapshot_retain_count="${NAS_UPDATE_STATE_RETAIN_COUNT:-3}"
if ! [[ "$state_snapshot_retain_count" =~ ^[0-9]+$ ]] || ! (( state_snapshot_retain_count <= 20 )); then
  echo "NAS_UPDATE_STATE_RETAIN_COUNT must be an integer between 0 and 20." >&2
  exit 2
fi

prune_state_snapshots() {
  [[ -d "$update_state_root" ]] || return 0
  local -a snapshots=()
  mapfile -t snapshots < <(
    find "$update_state_root" -maxdepth 1 -type f -name 'pre-activation-*.tar.gz' -printf '%T@ %p\n' \
      | sort -rn | cut -d' ' -f2-
  )
  local index
  for (( index=state_snapshot_retain_count; index<${#snapshots[@]}; index++ )); do
    rm -f -- "${snapshots[$index]}"
  done
}

create_state_snapshot() {
  local state_tool=/run/current-system/sw/bin/nas-state
  [[ -x "$state_tool" ]] || { echo "Installed nas-state tool is unavailable; refusing mutable-state activation." >&2; return 1; }
  install -d -m 0700 "$update_state_root"
  state_snapshot="$update_state_root/pre-activation-$(date +%s)-$(printf '%s' "$candidate_commit$deployment_dir" | sha256sum | cut -c1-12).tar.gz"
  "$state_tool" export "$state_snapshot" --include-sensitive >/dev/null
  [[ -s "$state_snapshot" ]] || { echo "Pre-activation state snapshot is empty." >&2; return 1; }
}

restore_state_snapshot() {
  [[ -n "$state_snapshot" && -s "$state_snapshot" ]] || return 0
  local state_tool="$old_system/sw/bin/nas-state"
  [[ -x "$state_tool" ]] || state_tool=/run/current-system/sw/bin/nas-state
  "$state_tool" restore "$state_snapshot" --apply \
    --confirm-host "$(cat /proc/sys/kernel/hostname)" \
    --allow-partial --include-sensitive --restore-absence
}

mark_manual_recovery() {
  local reason=$1 candidate_source="$deployment_dir"
  # Detached candidate worktrees are deleted by EXIT cleanup. Never record an
  # ephemeral path as recovery evidence; the exact commit is durable metadata.
  [[ -n "$candidate_worktree" ]] && candidate_source=""
  install -d -m 0700 "$update_state_root"
  jq -n \
    --arg reason "$reason" \
    --arg activeSource "$active_config_dir" \
    --arg candidateSource "$candidate_source" \
    --arg candidateCommit "$candidate_commit" \
    --arg oldSystem "$old_system" \
    --arg stateSnapshot "$state_snapshot" \
    --argjson createdAt "$(date +%s)" \
    '{schemaVersion:1,status:"manual-recovery-required",reason:$reason,activeSource:$activeSource,candidateSource:(if $candidateSource == "" then null else $candidateSource end),candidateCommit:(if $candidateCommit == "" then null else $candidateCommit end),oldSystem:$oldSystem,stateSnapshot:$stateSnapshot,createdAt:$createdAt}' \
    > "$manual_recovery_marker"
  chmod 0600 "$manual_recovery_marker"
}

old_system="$(readlink -f /run/current-system)"
system_profile=/nix/var/nix/profiles/system
old_profile="$(readlink -f "$system_profile" 2>/dev/null || true)"
old_profile_link="$(readlink "$system_profile" 2>/dev/null || true)"
rollback_needed=false
runtime_activation_attempted=false
rollback() {
  local rc=$?
  local -a rollback_errors=()
  if (( rc != 0 )) && $rollback_needed; then
    echo "Deployment failed; reversing only deployment phases that were entered" >&2
    current_profile_link="$(readlink "$system_profile" 2>/dev/null || true)"
    # Compare the link text, not the resolved store path: a failed switch that
    # never moved the profile must not roll the persistent profile back one
    # generation.
    if [[ -n "$old_profile_link" && "$current_profile_link" != "$old_profile_link" ]]; then
      nixos-rebuild --rollback switch || rollback_errors+=("nixos generation rollback failed")
    fi
    if $runtime_activation_attempted; then
      "$old_system/bin/switch-to-configuration" switch || rollback_errors+=("old generation activation failed")
      restored_profile="$(readlink -f "$system_profile" 2>/dev/null || true)"
      if [[ -n "$old_profile" && "$restored_profile" != "$old_profile" ]]; then
        rollback_errors+=("persistent system profile was not restored to $old_profile")
      fi
      restore_state_snapshot || rollback_errors+=("mutable application state restore failed")
      restart_protected || rollback_errors+=("protected stack restart failed")
    fi
    if $source_promoted && [[ -n "$original_source_commit" ]]; then
      if git_safe -C "$active_config_dir" reset --hard "$original_source_commit"; then
        source_promoted=false
      else
        rollback_errors+=("active source checkout rollback failed")
      fi
    fi
    if ((${#rollback_errors[@]})); then
      reason="$(IFS='; '; echo "${rollback_errors[*]}")"
      mark_manual_recovery "$reason" || true
      echo "Automatic rollback was incomplete: $reason" >&2
      rc=70
    fi
  fi
  cleanup_candidate
  exit "$rc"
}

trap rollback EXIT

if $apply; then
  # Reject an unusable independent-management probe before any build, snapshot,
  # or activation work; the launch still happens at each health gate.
  external_management_probe --validate
  # A pre-existing application failure is not evidence against the candidate;
  # refuse before any mutation instead of rolling back state afterwards.
  if $protected_was_active; then
    managed_services_settled || exit 1
    application_health || {
      echo "Refusing to apply: repair the units above or turn their applications off in Managed Services first." >&2
      exit 1
    }
  fi
fi

echo "Evaluating reviewed flake inputs without modifying flake.lock..."
nix flake metadata --no-write-lock-file >/dev/null
nix flake check --no-write-lock-file --show-trace

if [[ -x scripts/preflight.sh ]]; then
  NAS_PREFLIGHT_REQUIRE_COMPLETE=1 scripts/preflight.sh
fi

echo "Building without activation..."
nixos-rebuild build --flake "$flake_ref" --show-trace

if $apply; then
  # Reject a dangling system profile before activation: readlink -f resolves a
  # dangling link to a nonempty path whose target does not exist, so an empty
  # old_profile or a nonexistent link target means there is no usable rollback
  # baseline. -e follows the link, resolving relative targets from its directory.
  if [[ -z "$old_profile" || ! -e "$system_profile" ]]; then
    echo "The existing persistent system profile is missing or unreadable; refusing activation without a rollback baseline." >&2
    exit 1
  fi
  echo "Capturing mutable application state before candidate activation..."
  create_state_snapshot
  echo "Temporarily activating the candidate generation..."
  # Rollback becomes necessary only when candidate activation is about to begin.
  # Snapshot failures happen before any candidate mutation and leave the live
  # system untouched.
  runtime_activation_attempted=true
  rollback_needed=true
  nixos-rebuild test --flake "$flake_ref" --show-trace
  restart_protected
  health_check
  external_management_probe

  echo "Health checks passed; making the generation persistent."
  nixos-rebuild switch --flake "$flake_ref" --show-trace
  new_profile_link="$(readlink "$system_profile" 2>/dev/null || true)"
  [[ -n "$new_profile_link" && "$new_profile_link" != "$old_profile_link" ]] || { echo "Persistent system profile did not advance" >&2; exit 1; }
  restart_protected
  health_check
  external_management_probe
  if $sync; then
    echo "Promoting the validated source revision into the active checkout."
    git_safe -C "$active_config_dir" merge --ff-only "$candidate_commit"
    source_promoted=true
  fi
  rm -f "$manual_recovery_marker"
  rollback_needed=false
  prune_state_snapshots
elif $sync; then
  echo "Promoting the validated source revision into the active checkout."
  git_safe -C "$active_config_dir" merge --ff-only "$candidate_commit"
  source_promoted=true
fi

trap - EXIT
cleanup_candidate
if $apply; then
  echo "Deployment complete. Reboot remains a separate administrator decision."
elif $sync; then
  echo "Approved source synchronized and validated. No services or generations were changed."
else
  echo "Build complete. No files, pins, services, or generations were changed."
fi
