#!/usr/bin/env bash
set -Eeuo pipefail

fail() { printf 'live-validation: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "missing command: $1"; }
need_env() { [[ -n "${!1:-}" ]] || fail "set $1"; }
# confirm() authorizes a single drill. NAS_LIVE_CONFIRM is matched exactly, so
# NAS_LIVE_CONFIRM=SYNCOID_DRILL authorizes only the syncoid drill and a
# comma-separated list authorizes nothing. The `all` subcommand sets
# _LIVE_ALL_MODE and runs every drill in sequence.
confirm() { [[ -n "${_LIVE_ALL_MODE:-}" ]] && return 0; [[ "${NAS_LIVE_CONFIRM:-}" == "$1" ]] || fail "set NAS_LIVE_CONFIRM=$1"; }

read_secret_file() {
  local path=$1 mode
  [[ -f "$path" && ! -L "$path" ]] || fail "secret path must be a regular non-symlink file: $path"
  mode=$(stat -c '%a' "$path")
  (( (8#$mode & 8#077) == 0 )) || fail "secret file must not be group/world accessible: $path"
  IFS= read -r REPLY < "$path" || [[ -n "$REPLY" ]] || fail "secret file is empty: $path"
}

trusted_cockpit_probe() {
  need_env NAS_COCKPIT_URL
  need_env NAS_COCKPIT_CA_FILE
  [[ -f "$NAS_COCKPIT_CA_FILE" ]] || fail "Cockpit CA file is missing: $NAS_COCKPIT_CA_FILE"
  curl --fail --silent --show-error --cacert "$NAS_COCKPIT_CA_FILE" "$NAS_COCKPIT_URL" >/dev/null
}

remote_probe() {
  [[ -z "${NAS_REMOTE_PROBE_HOST:-}" ]] && return 0
  need ssh
  need_env NAS_REMOTE_COCKPIT_URL
  need_env NAS_REMOTE_COCKPIT_CA_FILE
  ssh -o BatchMode=yes "$NAS_REMOTE_PROBE_HOST" \
    curl --fail --silent --show-error --cacert "$NAS_REMOTE_COCKPIT_CA_FILE" "$NAS_REMOTE_COCKPIT_URL" >/dev/null
}

validate_dataset() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]*(/[A-Za-z0-9][A-Za-z0-9_.:-]*)*(@[A-Za-z0-9][A-Za-z0-9_.:-]*)?$ ]] \
    || fail "unsafe ZFS dataset or snapshot name: $1"
}

remote_zfs() {
  local host=$1 action=$2 first=$3 second=${4:-}
  validate_dataset "$first"
  [[ -z "$second" ]] || validate_dataset "$second"
  # Create and clone targets must be datasets, never snapshot-qualified names
  if [[ "$action" == "clone" && -n "$second" && "$second" == *"@"* ]]; then
    fail "clone target must not be snapshot-qualified: $second"
  fi
  if [[ "$action" == "create" && "$first" == *"@"* ]]; then
    fail "create target must not be snapshot-qualified: $first"
  fi
  # shellcheck disable=SC2016
  printf '%s\n' \
    'set -Eeuo pipefail' \
    'action=$1; first=$2; second=${3:-}' \
    'case "$action" in' \
    '  clone) exec zfs clone -- "$first" "$second" ;;' \
    '  create) exec zfs create -- "$first" ;;' \
    '  destroy) exec zfs destroy -- "$first" ;;' \
    '  mountpoint) exec zfs get -H -o value mountpoint "$first" ;;' \
    '  *) exit 64 ;;' \
    'esac' \
    | ssh -o BatchMode=yes "$host" bash -s -- "$action" "$first" "$second"
}

curl_config_escape() {
  local value=$1
  local escaped
  if ! escaped=$(printf '%s' "$value" | python3 -c '
import sys
s = sys.stdin.read()
out = []
for ch in s:
    code = ord(ch)
    if ch == "\\": out.append("\\\\")
    elif ch == "\"": out.append("\\\"")
    elif ch == "\t": out.append("\\t")
    elif ch == "\n": out.append("\\n")
    elif ch == "\r": out.append("\\r")
    elif ch == "\v": out.append("\\v")
    elif code < 0x20 or code == 0x7f: raise SystemExit("unsupported control character in curl config value")
    else: out.append(ch)
sys.stdout.write("".join(out))
'); then
    return 1
  fi
  printf '%s' "$escaped"
}

curl_basic() {
  local username=$1 password=$2
  shift 2
  local user_escaped pass_escaped
  user_escaped=$(curl_config_escape "$username") || fail "curl_config_escape failed for username"
  pass_escaped=$(curl_config_escape "$password") || fail "curl_config_escape failed for password"
  printf 'user = "%s:%s"\n' "$user_escaped" "$pass_escaped" \
    | curl --config - "$@"
}

curl_bearer() {
  local token=$1
  shift
  local token_escaped
  token_escaped=$(curl_config_escape "$token") || fail "curl_config_escape failed for token"
  printf 'header = "Authorization: Bearer %s"\n' "$token_escaped" \
    | curl --config - "$@"
}

locked_boot() {
  confirm LOCKED_BOOT
  need curl
  need systemctl
  need_env NAS_KEEPASS_PASSWORD_FILE
  read_secret_file "$NAS_KEEPASS_PASSWORD_FILE"
  local keepass_password=$REPLY
  sudo -u "${NAS_ADMIN_USER:-admin}" nas-secrets stop
  for unit in authentik.service copyparty.service caddy.service; do
    ! systemctl is-active --quiet "$unit" || fail "$unit remained active"
  done
  [[ ! -e /run/nas-secrets/ready ]] || fail "secret readiness marker remained after lock"
  trusted_cockpit_probe
  remote_probe
  if [[ -n "${NAS_WRONG_KEEPASS_PASSWORD_FILE:-}" ]]; then
    read_secret_file "$NAS_WRONG_KEEPASS_PASSWORD_FILE"
    ! printf '%s\n' "$REPLY" | sudo -u "${NAS_ADMIN_USER:-admin}" nas-secrets activate-stdin \
      || fail "incorrect KeePass password was accepted"
    [[ ! -e /run/nas-secrets/ready ]] || fail "failed activation committed a readiness marker"
  fi
  printf '%s\n' "$keepass_password" | sudo -u "${NAS_ADMIN_USER:-admin}" nas-secrets activate-stdin
  systemctl is-active --quiet nas-protected-services.target
  [[ -f /run/nas-secrets/ready ]] || fail "secret readiness marker is missing"
  nas-zfs-mount-check
}

copyparty() {
  need curl
  need_env NAS_COPY_USER
  need_env NAS_COPY_PASSWORD_FILE
  need_env NAS_COPY_BASE_URL
  read_secret_file "$NAS_COPY_PASSWORD_FILE"
  local password=$REPLY stamp remote
  # Cleanup state is global on purpose: when a command fails under errexit, bash
  # unwinds the function's locals before running the EXIT trap.
  _copyparty_temp=""
  _copyparty_downloaded=""
  cleanup_copyparty() {
    [[ -z "${_copyparty_temp:-}" ]] || rm -f -- "$_copyparty_temp"
    [[ -z "${_copyparty_downloaded:-}" ]] || rm -f -- "$_copyparty_downloaded"
    _copyparty_temp=""
    _copyparty_downloaded=""
  }
  # Registered before the second allocation so a failure there cannot leak the
  # first file. RETURN covers a normal finish, EXIT covers failure paths.
  trap cleanup_copyparty RETURN
  trap cleanup_copyparty EXIT
  _copyparty_temp=$(mktemp) || fail "failed to create temp file"
  _copyparty_downloaded=$(mktemp) || fail "failed to create downloaded temp file"
  stamp=$(date -u +%Y%m%d%H%M%S)
  printf 'nas live validation %s\n' "$(date -u +%FT%TZ)" > "$_copyparty_temp"
  nas-identity-sync sync >/dev/null
  if [[ -n "${NAS_COPY_EXPECTED_PATH:-}" ]]; then
    [[ -d "$NAS_COPY_EXPECTED_PATH" ]] || fail "personal volume path is missing: $NAS_COPY_EXPECTED_PATH"
  fi
  remote="${NAS_COPY_BASE_URL%/}/nas-live-$stamp-$$.txt"
  curl_basic "$NAS_COPY_USER" "$password" --fail --silent --show-error --upload-file "$_copyparty_temp" "$remote"
  curl_basic "$NAS_COPY_USER" "$password" --fail --silent --show-error "$remote" > "$_copyparty_downloaded"
  cmp "$_copyparty_temp" "$_copyparty_downloaded"
  curl_basic "$NAS_COPY_USER" "$password" --fail --silent --show-error -X DELETE "$remote" >/dev/null
  if [[ -n "${NAS_COPY_NATIVE_SHARE_URL:-}" ]]; then
    curl --fail --silent --show-error "$NAS_COPY_NATIVE_SHARE_URL" >/dev/null
  fi
}

syncoid_drill() {
  confirm SYNCOID_DRILL
  need syncoid
  need zfs
  need_env NAS_SYNCOID_SOURCE
  need_env NAS_SYNCOID_TARGET
  # Validate source and target dataset names before any ZFS operations
  validate_dataset "${NAS_SYNCOID_SOURCE%%/*}"
  _syncoid_remote=false
  if [[ "$NAS_SYNCOID_TARGET" == *:* ]]; then
    _syncoid_remote=true
    validate_dataset "${NAS_SYNCOID_TARGET#*:}"
    need ssh
  else
    validate_dataset "${NAS_SYNCOID_TARGET%/}"
  fi
  # Reject identical local source and target: Syncoid would replicate the
  # dataset onto itself and the marker check would read the source, not a copy.
  if [[ "$_syncoid_remote" == false && "${NAS_SYNCOID_TARGET%/}" == "${NAS_SYNCOID_SOURCE%/}" ]]; then
    fail "source and target must not be identical: $NAS_SYNCOID_SOURCE"
  fi
  # Cleanup state is global on purpose: when a command fails under errexit, bash
  # unwinds the function's locals before running the EXIT trap.
  local stamp mountpoint marker syncoid_target
  _syncoid_host=""
  _syncoid_claim=""
  _syncoid_target_dataset=""
  _syncoid_clone=""
  _syncoid_child=""
  _syncoid_snapshot=""
  _syncoid_owned_child=false
  _syncoid_owned_snapshot=false
  _syncoid_owned_target=false
  _syncoid_owned_clone=false
  stamp=$(date -u +%Y%m%d%H%M%S)
  _syncoid_child="${NAS_SYNCOID_SOURCE%/}/nas-live-$stamp"
  _syncoid_snapshot="$_syncoid_child@validation"
  marker="nas-live-$stamp"
  validate_dataset "$_syncoid_child"
  validate_dataset "$_syncoid_snapshot"
  # Resolve both destinations and prove they are unused before the drill writes
  # anything. Ownership is recorded only after the matching operation succeeds,
  # and every destroy below is guarded by it, so cleanup can never remove a
  # dataset another writer owns.
  #
  # The destination is claimed by an atomic `zfs create` of a parent dataset
  # rather than by the existence probes alone: `zfs create` is the only race-free
  # arbiter available, so the writer whose create succeeds owns the name and every
  # other writer gets EEXIST. Syncoid performs initial replication only into a
  # non-existent target, so the replica is written to a child of the claim.
  if [[ "$_syncoid_remote" == true ]]; then
    _syncoid_host=${NAS_SYNCOID_TARGET%%:*}
    [[ -n "$_syncoid_host" ]] || fail "remote target must include a host: $NAS_SYNCOID_TARGET"
    _syncoid_claim="${NAS_SYNCOID_TARGET#*:}/nas-live-$stamp"
  else
    _syncoid_claim="${NAS_SYNCOID_TARGET%/}/nas-live-$stamp"
  fi
  _syncoid_target_dataset="$_syncoid_claim/replica"
  if [[ "$_syncoid_remote" == true ]]; then
    syncoid_target="$_syncoid_host:$_syncoid_target_dataset"
    _syncoid_clone="${NAS_SYNCOID_REMOTE_CLONE:-${_syncoid_target_dataset}-restore}"
  else
    syncoid_target="$_syncoid_target_dataset"
    _syncoid_clone="${NAS_SYNCOID_LOCAL_CLONE:-${_syncoid_target_dataset}-restore}"
  fi
  validate_dataset "$_syncoid_claim"
  validate_dataset "$_syncoid_target_dataset"
  validate_dataset "$_syncoid_clone"
  [[ "$_syncoid_clone" != *"@"* ]] || fail "clone target must not be snapshot-qualified: $_syncoid_clone"
  [[ "$_syncoid_clone" != "$_syncoid_child" && "$_syncoid_clone" != "$_syncoid_claim" \
    && "$_syncoid_clone" != "$_syncoid_target_dataset" ]] \
    || fail "drill clone must differ from source and target"
  if [[ "$_syncoid_remote" == true ]]; then
    if remote_zfs "$_syncoid_host" mountpoint "$_syncoid_claim" >/dev/null 2>&1; then
      fail "remote destination already exists: $_syncoid_claim"
    fi
    if remote_zfs "$_syncoid_host" mountpoint "$_syncoid_clone" >/dev/null 2>&1; then
      fail "remote clone destination already exists: $_syncoid_clone"
    fi
  else
    if zfs get -H -o value mountpoint "$_syncoid_claim" >/dev/null 2>&1; then
      fail "local destination already exists: $_syncoid_claim"
    fi
    if zfs get -H -o value mountpoint "$_syncoid_clone" >/dev/null 2>&1; then
      fail "local clone destination already exists: $_syncoid_clone"
    fi
  fi
  if zfs get -H -o value mountpoint "$_syncoid_child" >/dev/null 2>&1; then
    fail "drill child already exists: $_syncoid_child"
  fi
  cleanup_syncoid() {
    local _errexit_was_on=false
    shopt -qo errexit && _errexit_was_on=true
    set +e
    # Destroy only datasets this run successfully created or replicated. Never
    # recurse into a root that may hold foreign (another writer's) children. The
    # destination claim is removed only after the replica inside it was proven to
    # be this run's copy, so a partial destination stays for inspection.
    if [[ "${_syncoid_remote:-false}" == true ]]; then
      [[ -z "${_syncoid_clone:-}" || "${_syncoid_owned_clone:-false}" == false ]] \
        || remote_zfs "$_syncoid_host" destroy "$_syncoid_clone" >/dev/null 2>&1
      [[ -z "${_syncoid_target_dataset:-}" || "${_syncoid_owned_target:-false}" == false ]] \
        || remote_zfs "$_syncoid_host" destroy "$_syncoid_target_dataset" >/dev/null 2>&1
      [[ -z "${_syncoid_claim:-}" || "${_syncoid_owned_target:-false}" == false ]] \
        || remote_zfs "$_syncoid_host" destroy "$_syncoid_claim" >/dev/null 2>&1
    else
      [[ -z "${_syncoid_clone:-}" || "${_syncoid_owned_clone:-false}" == false ]] \
        || zfs destroy -- "$_syncoid_clone" >/dev/null 2>&1
      [[ -z "${_syncoid_target_dataset:-}" || "${_syncoid_owned_target:-false}" == false ]] \
        || zfs destroy -- "$_syncoid_target_dataset" >/dev/null 2>&1
      [[ -z "${_syncoid_claim:-}" || "${_syncoid_owned_target:-false}" == false ]] \
        || zfs destroy -- "$_syncoid_claim" >/dev/null 2>&1
    fi
    # Destroy our snapshot first, then the dataset non-recursively so foreign
    # child datasets created by another writer are not destroyed.
    [[ -z "${_syncoid_snapshot:-}" || "${_syncoid_owned_snapshot:-false}" == false ]] \
      || zfs destroy -- "$_syncoid_snapshot" >/dev/null 2>&1
    [[ -z "${_syncoid_child:-}" || "${_syncoid_owned_child:-false}" == false ]] \
      || zfs destroy -- "$_syncoid_child" >/dev/null 2>&1
    # Clear the state so RETURN followed by EXIT is a no-op.
    _syncoid_clone=""
    _syncoid_target_dataset=""
    _syncoid_claim=""
    _syncoid_snapshot=""
    _syncoid_child=""
    _syncoid_owned_clone=false
    _syncoid_owned_target=false
    _syncoid_owned_snapshot=false
    _syncoid_owned_child=false
    # Restore errexit without eval (avoids security-scanner flag on eval builtin)
    if $_errexit_was_on; then
      set -e
    else
      set +e
    fi
  }
  # RETURN covers a normal finish; EXIT covers failure paths. Cleanup is
  # idempotent because the state above is cleared as each dataset is removed.
  trap cleanup_syncoid RETURN
  trap cleanup_syncoid EXIT
  zfs create -- "$_syncoid_child"
  _syncoid_owned_child=true
  mountpoint=$(zfs get -H -o value mountpoint "$_syncoid_child")
  printf '%s\n' "$marker" > "$mountpoint/marker.txt"
  zfs snapshot -- "$_syncoid_snapshot"
  _syncoid_owned_snapshot=true
  # Claim the destination atomically before replication. Losing this create to
  # another writer aborts the drill, and the loser never destroys the winner's
  # dataset because ownership is recorded only on success. The claim is taken
  # after the source child exists and immediately before syncoid runs, so no
  # failure between the two can strand an empty claim.
  if [[ "$_syncoid_remote" == true ]]; then
    remote_zfs "$_syncoid_host" create "$_syncoid_claim" >/dev/null \
      || fail "could not claim remote destination: $_syncoid_claim (owned by another writer, or its parent dataset is missing)"
  else
    zfs create -- "$_syncoid_claim" >/dev/null \
      || fail "could not claim local destination: $_syncoid_claim (owned by another writer, or its parent dataset is missing)"
  fi
  # A failed replication can leave a partial destination. Leave it for operator
  # inspection instead of claiming ownership of an incomplete copy.
  if ! syncoid --no-sync-snap "$_syncoid_child" "$syncoid_target"; then
    fail "syncoid replication to $syncoid_target failed; leaving the destination for inspection"
  fi
  # Prove the replica is this run's copy from the marker the drill wrote into the
  # source child. Only then may cleanup remove the destination.
  if [[ "$_syncoid_remote" == true ]]; then
    mountpoint=$(remote_zfs "$_syncoid_host" mountpoint "$_syncoid_target_dataset")
    [[ "$(ssh -o BatchMode=yes "$_syncoid_host" cat -- "$mountpoint/marker.txt")" == "$marker" ]] \
      || fail "replicated marker mismatch at $_syncoid_target_dataset"
  else
    [[ "$(cat "$(zfs get -H -o value mountpoint "$_syncoid_target_dataset")/marker.txt")" == "$marker" ]] \
      || fail "replicated marker mismatch at $_syncoid_target_dataset"
  fi
  _syncoid_owned_target=true
  # `zfs clone` is itself an atomic claim: it fails when the name is taken, so a
  # clone name lost to another writer is never recorded as ours.
  if [[ "$_syncoid_remote" == true ]]; then
    remote_zfs "$_syncoid_host" clone "$_syncoid_target_dataset@validation" "$_syncoid_clone"
    _syncoid_owned_clone=true
    mountpoint=$(remote_zfs "$_syncoid_host" mountpoint "$_syncoid_clone")
    [[ "$(ssh -o BatchMode=yes "$_syncoid_host" cat -- "$mountpoint/marker.txt")" == "$marker" ]] \
      || fail "restored marker mismatch at $_syncoid_clone"
  else
    zfs clone -- "$_syncoid_target_dataset@validation" "$_syncoid_clone"
    _syncoid_owned_clone=true
    [[ "$(cat "$(zfs get -H -o value mountpoint "$_syncoid_clone")/marker.txt")" == "$marker" ]] \
      || fail "restored marker mismatch at $_syncoid_clone"
  fi
  if [[ "$_syncoid_remote" == true ]]; then
    remote_zfs "$_syncoid_host" destroy "$_syncoid_clone" >/dev/null 2>&1 \
      || fail "could not destroy drill clone: $_syncoid_clone"
  else
    zfs destroy -- "$_syncoid_clone" >/dev/null 2>&1 || fail "could not destroy drill clone: $_syncoid_clone"
  fi
  _syncoid_owned_clone=false
  _syncoid_clone=""
  # Destroy our snapshot first, then the dataset non-recursively to avoid
  # destroying foreign child datasets.
  zfs destroy -- "$_syncoid_snapshot" >/dev/null 2>&1 || fail "could not destroy drill snapshot: $_syncoid_snapshot"
  _syncoid_owned_snapshot=false
  zfs destroy -- "$_syncoid_child" >/dev/null 2>&1 || fail "could not destroy drill source: $_syncoid_child"
  _syncoid_owned_child=false
}

restic_drill() {
  confirm RESTIC_DRILL
  need jq
  need restic
  need_env RESTIC_REPOSITORY
  need_env RESTIC_PASSWORD_FILE
  need_env NAS_RESTIC_SOURCE
  need_env NAS_RESTIC_RESTORE_TARGET
  local stamp run_id snapshot_id restored
  stamp=$(date -u +%Y%m%d%H%M%S)
  [[ -d "$NAS_RESTIC_SOURCE" ]] || install -d -m 0700 "$NAS_RESTIC_SOURCE"
  mkdir -p -- "$NAS_RESTIC_RESTORE_TARGET"
  # Cleanup state is global on purpose: when a command fails under errexit, bash
  # unwinds the function's locals before running the EXIT trap.
  _restic_marker=""
  _restic_restore_root=""
  _restic_restore_root=$(mktemp -d "$NAS_RESTIC_RESTORE_TARGET/nas-live-$stamp.XXXXXX")
  run_id=$(basename -- "$_restic_restore_root")
  _restic_marker="$NAS_RESTIC_SOURCE/.$run_id"
  # Restic restores the backup source below --target. Strip any leading slash and
  # always join with one separator so a relative NAS_RESTIC_SOURCE resolves.
  restored="$_restic_restore_root/${NAS_RESTIC_SOURCE#/}/.$run_id"
  cleanup_restic() {
    [[ -z "${_restic_marker:-}" ]] || rm -f -- "$_restic_marker"
    [[ -z "${_restic_restore_root:-}" ]] || rm -rf -- "$_restic_restore_root"
    _restic_marker=""
    _restic_restore_root=""
  }
  # RETURN covers a normal finish; EXIT covers failure paths.
  trap cleanup_restic RETURN
  trap cleanup_restic EXIT
  printf '%s\n' "$stamp" > "$_restic_marker"
  snapshot_id=$(restic backup --json "$NAS_RESTIC_SOURCE" | jq -r 'select(.message_type == "summary") | .snapshot_id')
  [[ -n "$snapshot_id" && "$snapshot_id" != null ]] || fail "restic did not return a snapshot id"
  restic restore "$snapshot_id" --target "$_restic_restore_root"
  cmp "$_restic_marker" "$restored"
}

authentik() {
  need curl
  need jq
  need python3
  need_env NAS_AUTHENTIK_ORIGIN
  need_env NAS_AUTHENTIK_TOKEN_FILE
  need_env NAS_OPERATOR_PASSWORD_FILE
  need_env NAS_ALICE_PASSWORD_FILE
  need_env NAS_BASELINE_PASSWORD_FILE
  read_secret_file "$NAS_AUTHENTIK_TOKEN_FILE"
  local token=$REPLY
  curl_bearer "$token" --fail --silent --show-error \
    "$NAS_AUTHENTIK_ORIGIN/api/v3/managed/blueprints/?search=NAS%20user%20settings" \
    | jq -e '.results | length >= 1' >/dev/null
  python3 "${NAS_SOURCE_ROOT:-.}/tests/browser/authz.py" \
    --origin "$NAS_AUTHENTIK_ORIGIN" \
    --operator-password-file "$NAS_OPERATOR_PASSWORD_FILE" \
    --alice-password-file "$NAS_ALICE_PASSWORD_FILE" \
    --baseline-password-file "$NAS_BASELINE_PASSWORD_FILE"
}

observability() {
  need curl
  need jq
  need systemctl
  local stamp metric alert i
  stamp=$(date +%s)
  metric="nas_live_validation,run=$stamp value=1i"
  curl --fail --silent --show-error --data-binary "$metric" \
    http://127.0.0.1:8428/victoriametrics/write >/dev/null
  # Poll for visibility: query on every iteration and sleep only when another
  # query follows, so a sample that appears late in the window is still seen.
  for ((i = 1; i <= 11; i++)); do
    if curl --fail --silent --show-error \
      "http://127.0.0.1:8428/victoriametrics/api/v1/query?query=nas_live_validation_value%7Brun%3D%22$stamp%22%7D&offset=0" \
      | jq -e '.status == "success" and (.data.result | length) == 1' >/dev/null; then
      break
    fi
    if ((i == 11)); then
      fail "victoriaMetrics sample not visible for run $stamp"
    fi
    sleep 5
  done
  curl --fail --silent --show-error http://127.0.0.1:8880/-/healthy >/dev/null
  curl --fail --silent --show-error http://127.0.0.1:8880/api/v1/rules \
    | jq -e '.status == "success"' >/dev/null
  curl --fail --silent --show-error http://127.0.0.1:9093/-/ready >/dev/null
  alert=$(jq -nc --arg stamp "$stamp" '[{labels:{alertname:"NasLiveValidation",severity:"info",run:$stamp},annotations:{summary:"NAS live validation"},startsAt:(now|todate),endsAt:(now+300|todate)}]')
  curl --fail --silent --show-error -H 'Content-Type: application/json' --data "$alert" http://127.0.0.1:9093/api/v2/alerts >/dev/null
  curl --fail --silent --show-error http://127.0.0.1:9093/api/v2/alerts \
    | jq -e --arg stamp "$stamp" 'any(.[]; .labels.alertname == "NasLiveValidation" and .labels.run == $stamp)' >/dev/null
  systemctl show -p ExecStart victoriametrics.service | grep -q -- '-retentionPeriod='
  if systemctl is-active --quiet ntfy-sh.service; then
    need_env NAS_NTFY_TOPIC_FILE
    read_secret_file "$NAS_NTFY_TOPIC_FILE"
    curl --fail --silent --show-error "http://127.0.0.1:2586/$REPLY/json?poll=1&since=all" >/dev/null
  fi
}

case "${1:-}" in
  locked-boot) locked_boot ;;
  copyparty) copyparty ;;
  syncoid) syncoid_drill ;;
  restic) restic_drill ;;
  authentik) authentik ;;
  observability) observability ;;
  all) _LIVE_ALL_MODE=1; confirm ALL; locked_boot; copyparty; syncoid_drill; restic_drill; authentik; observability ;;
  *) fail "usage: $0 {locked-boot|copyparty|syncoid|restic|authentik|observability|all}" ;;
esac
