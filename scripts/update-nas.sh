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
                Normal deployment requires NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON.
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
candidate_commit=""
source_promoted=false
original_source_commit=""
authentik_port="${NAS_AUTHENTIK_PORT:-9000}"
authentik_path="${NAS_AUTHENTIK_PATH:-/identity/}"
caddy_ca_file="${NAS_CADDY_CA_FILE:-/run/nas-caddy-ca/ca-bundle.crt}"
cockpit_port="${NAS_COCKPIT_PORT:-9092}"
firewall_enabled="${NAS_FIREWALL_ENABLED:-1}"
firewall_zone="${NAS_FIREWALL_ZONE:-nas-lan}"
lan_host="${NAS_LAN_HOST:-$(cat /proc/sys/kernel/hostname).local}"
trusted_interfaces="${NAS_TRUSTED_INTERFACES:-}"

for command in nix nixos-rebuild systemctl zfs zpool curl readlink sha256sum git jq ip ss firewall-cmd; do
  command -v "$command" >/dev/null 2>&1 || { echo "Missing command: $command" >&2; exit 1; }
done

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
}
trap cleanup_candidate EXIT

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
  if $json_output; then
    jq -n \
      --arg configurationDir "$config_dir" \
      --arg revision "$revision" \
      --arg branch "$branch" \
      --arg upstream "$upstream" \
      --arg currentSystem "$current_system" \
      --argjson git "$inside_git" \
      --argjson dirty "$dirty" \
      --argjson ahead "$ahead" \
      --argjson behind "$behind" \
      '{configurationDir:$configurationDir, git:$git, revision:$revision, branch:$branch, upstream:(if $upstream == "" then null else $upstream end), ahead:$ahead, behind:$behind, dirty:$dirty, currentSystem:$currentSystem}'
  else
    printf 'Configuration: %s\nRevision: %s\nBranch: %s\nUpstream: %s\nDirty: %s\nCurrent system: %s\n' \
      "$config_dir" "$revision" "$branch" "${upstream:-none}" "$dirty" "$current_system"
  fi
  exit 0
fi

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
  candidate_worktree="$(mktemp -d /var/tmp/nas-update-candidate.XXXXXX)"
  rmdir "$candidate_worktree"
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
  if [[ -z "$raw" ]]; then
    $allow_local_health_only && {
      echo "WARNING: persisting after local-only management checks by explicit override." >&2
      return 0
    }
    echo "Persistent deployment requires NAS_UPDATE_EXTERNAL_PROBE_COMMAND_JSON from an independent management path, or --allow-local-health-only for recovery." >&2
    return 1
  fi
  local -a probe=()
  mapfile -d '' -t probe < <(python3 - "$raw" <<'PY_EXTERNAL_PROBE'
import json
import sys
value = json.loads(sys.argv[1])
if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
    raise SystemExit("external probe command must be a nonempty JSON string array")
for item in value:
    if "\x00" in item:
        raise SystemExit("external probe argument contains NUL")
    sys.stdout.buffer.write(item.encode() + b"\0")
PY_EXTERNAL_PROBE
  )
  ((${#probe[@]})) || { echo "External management probe command is empty." >&2; return 1; }
  timeout 60 "${probe[@]}"
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
    for unit in postgresql.service authentik-worker.service authentik.service copyparty.service cockpit.socket caddy.service; do
      systemctl is-active --quiet "$unit" || { echo "$unit is not active" >&2; return 1; }
    done
    [[ -S /run/copyparty/http.sock ]]
    listener_present "$cockpit_port" || { echo "Cockpit is not listening on $cockpit_port" >&2; return 1; }
    listener_present 443 || { echo "Caddy is not listening on 443" >&2; return 1; }
    curl --fail --silent --show-error --max-time 10 "http://127.0.0.1:${authentik_port}${authentik_path}-/health/ready/" >/dev/null
    curl --fail --silent --show-error --max-time 10 --unix-socket /run/copyparty/http.sock http://localhost/ >/dev/null
    management_route_reachable
  fi
}

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
rollback_needed=false
runtime_activation_attempted=false
persistent_switch_attempted=false
rollback() {
  local rc=$?
  local -a rollback_errors=()
  if (( rc != 0 )) && $rollback_needed; then
    echo "Deployment failed; reversing only deployment phases that were entered" >&2
    current_profile="$(readlink -f "$system_profile" 2>/dev/null || true)"
    if $persistent_switch_attempted || [[ -n "$old_profile" && "$current_profile" != "$old_profile" ]]; then
      nixos-rebuild switch --rollback || rollback_errors+=("nixos generation rollback failed")
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

echo "Evaluating reviewed flake inputs without modifying flake.lock..."
nix flake metadata --no-write-lock-file >/dev/null
nix flake check --no-write-lock-file --show-trace

if [[ -x scripts/preflight.sh ]]; then
  NAS_PREFLIGHT_REQUIRE_COMPLETE=1 scripts/preflight.sh
fi

echo "Building without activation..."
nixos-rebuild build --flake "$flake_ref" --show-trace

if $apply; then
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
  persistent_switch_attempted=true
  nixos-rebuild switch --flake "$flake_ref" --show-trace
  new_profile="$(readlink -f "$system_profile" 2>/dev/null || true)"
  [[ -n "$new_profile" && "$new_profile" != "$old_profile" ]] || { echo "Persistent system profile did not advance" >&2; exit 1; }
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
