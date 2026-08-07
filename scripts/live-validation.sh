#!/usr/bin/env bash
set -Eeuo pipefail

fail() { printf 'live-validation: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "missing command: $1"; }
need_env() { [[ -n "${!1:-}" ]] || fail "set $1"; }
confirm() { [[ "${NAS_LIVE_CONFIRM:-}" == "$1" ]] || fail "set NAS_LIVE_CONFIRM=$1"; }

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
  # shellcheck disable=SC2016
  printf '%s
' \
    'set -Eeuo pipefail' \
    'action=$1; first=$2; second=${3:-}' \
    'case "$action" in' \
    '  clone) exec zfs clone -- "$first" "$second" ;;' \
    '  destroy) exec zfs destroy -- "$first" ;;' \
    '  mountpoint) exec zfs get -H -o value mountpoint "$first" ;;' \
    '  *) exit 64 ;;' \
    'esac' \
    | ssh -o BatchMode=yes "$host" bash -s -- "$action" "$first" "$second"
}

curl_config_escape() {
  local value=$1
  printf '%s' "$value" | python3 -c '
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
'
}

curl_basic() {
  local username=$1 password=$2
  shift 2
  printf 'user = "%s:%s"\n' "$(curl_config_escape "$username")" "$(curl_config_escape "$password")" \
    | curl --config - "$@"
}

curl_bearer() {
  local token=$1
  shift
  printf 'header = "Authorization: Bearer %s"\n' "$(curl_config_escape "$token")" \
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
  local password=$REPLY temp remote downloaded
  temp=$(mktemp)
  downloaded=$(mktemp)
  trap 'rm -f "$temp" "$downloaded"' RETURN
  printf 'nas live validation %s\n' "$(date -u +%FT%TZ)" > "$temp"
  nas-identity-sync sync >/dev/null
  if [[ -n "${NAS_COPY_EXPECTED_PATH:-}" ]]; then
    [[ -d "$NAS_COPY_EXPECTED_PATH" ]] || fail "personal volume path is missing: $NAS_COPY_EXPECTED_PATH"
  fi
  remote="${NAS_COPY_BASE_URL%/}/nas-live-validation.txt"
  curl_basic "$NAS_COPY_USER" "$password" --fail --silent --show-error --upload-file "$temp" "$remote"
  curl_basic "$NAS_COPY_USER" "$password" --fail --silent --show-error "$remote" > "$downloaded"
  cmp "$temp" "$downloaded"
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
  local stamp child snapshot mountpoint marker target_dataset target_host clone cleanup_remote=false
  stamp=$(date -u +%Y%m%d%H%M%S)
  child="${NAS_SYNCOID_SOURCE}/nas-live-$stamp"
  snapshot="$child@validation"
  validate_dataset "$child"
  validate_dataset "$snapshot"
  cleanup_syncoid() {
    set +e
    if "$cleanup_remote"; then
      remote_zfs "$target_host" destroy "$clone" >/dev/null 2>&1 || true
      remote_zfs "$target_host" destroy "$target_dataset" >/dev/null 2>&1 || true
    else
      [[ -z "${clone:-}" ]] || zfs destroy -r -- "$clone" >/dev/null 2>&1 || true
      [[ -z "${target_dataset:-}" ]] || zfs destroy -r -- "$target_dataset" >/dev/null 2>&1 || true
    fi
    zfs destroy -r -- "$child" >/dev/null 2>&1 || true
  }
  trap cleanup_syncoid RETURN
  zfs create -- "$child"
  mountpoint=$(zfs get -H -o value mountpoint "$child")
  marker="nas-live-$stamp"
  printf '%s
' "$marker" > "$mountpoint/marker.txt"
  zfs snapshot -- "$snapshot"
  syncoid --no-sync-snap "$child" "${NAS_SYNCOID_TARGET%/}/nas-live-$stamp"
  if [[ "$NAS_SYNCOID_TARGET" == *:* ]]; then
    need ssh
    target_host=${NAS_SYNCOID_TARGET%%:*}
    target_dataset=${NAS_SYNCOID_TARGET#*:}/nas-live-$stamp
    clone="${NAS_SYNCOID_REMOTE_CLONE:-${target_dataset}-restore}"
    validate_dataset "$target_dataset"
    validate_dataset "$clone"
    cleanup_remote=true
    remote_zfs "$target_host" clone "$target_dataset@validation" "$clone"
    remote_mount=$(remote_zfs "$target_host" mountpoint "$clone")
    [[ "$(ssh -o BatchMode=yes "$target_host" cat -- "$remote_mount/marker.txt")" == "$marker" ]]
    remote_zfs "$target_host" destroy "$clone"
    clone=""
  else
    target_dataset="${NAS_SYNCOID_TARGET%/}/nas-live-$stamp"
    clone="${NAS_SYNCOID_LOCAL_CLONE:-${target_dataset}-restore}"
    validate_dataset "$target_dataset"
    validate_dataset "$clone"
    zfs clone -- "$target_dataset@validation" "$clone"
    [[ "$(cat "$(zfs get -H -o value mountpoint "$clone")/marker.txt")" == "$marker" ]]
    zfs destroy -- "$clone"
    clone=""
  fi
  zfs destroy -r -- "$child"
  child=""
}

restic_drill() {
  confirm RESTIC_DRILL
  need jq
  need restic
  need_env RESTIC_REPOSITORY
  need_env RESTIC_PASSWORD_FILE
  need_env NAS_RESTIC_SOURCE
  need_env NAS_RESTIC_RESTORE_TARGET
  local stamp marker snapshot_id restored restore_root
  stamp=$(date -u +%Y%m%d%H%M%S)
  marker="$NAS_RESTIC_SOURCE/.nas-live-$stamp"
  restore_root="$NAS_RESTIC_RESTORE_TARGET/nas-live-$stamp"
  restored="$restore_root${NAS_RESTIC_SOURCE}/.nas-live-$stamp"
  cleanup_restic() {
    rm -f -- "$marker"
    rm -rf -- "$restore_root"
  }
  trap cleanup_restic RETURN
  install -d -m 0700 "$NAS_RESTIC_SOURCE" "$restore_root"
  printf '%s
' "$stamp" > "$marker"
  snapshot_id=$(restic backup --json "$NAS_RESTIC_SOURCE" | jq -r 'select(.message_type == "summary") | .snapshot_id')
  [[ -n "$snapshot_id" && "$snapshot_id" != null ]] || fail "restic did not return a snapshot id"
  restic restore "$snapshot_id" --target "$restore_root"
  cmp "$marker" "$restored"
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
  local stamp metric alert
  stamp=$(date +%s)
  metric="nas_live_validation,run=$stamp value=1i"
  curl --fail --silent --show-error --data-binary "$metric" \
    http://127.0.0.1:8428/victoriametrics/write >/dev/null
  curl --fail --silent --show-error \
    "http://127.0.0.1:8428/victoriametrics/api/v1/query?query=nas_live_validation_value%7Brun%3D%22$stamp%22%7D" \
    | jq -e '.status == "success" and (.data.result | length) == 1' >/dev/null
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
  all) locked_boot; copyparty; syncoid_drill; restic_drill; authentik; observability ;;
  *) fail "usage: $0 {locked-boot|copyparty|syncoid|restic|authentik|observability|all}" ;;
esac
