#!/usr/bin/env bash
set -Eeuo pipefail

ZFS_DEVICE="${1:-${NAS_TEST_ZFS_DEVICE:-/dev/vdb}}"
KEEPASS_PASSWORD="${NAS_TEST_KEEPASS_PASSWORD:-nixos-nas-vm-test-password}"
PUBLIC_HOST="${NAS_TEST_PUBLIC_HOST:-nas-test.local}"
AUTHENTIK_PUBLIC_HOST="${NAS_TEST_AUTHENTIK_PUBLIC_HOST:-nas-test.local:8443}"
CONFIG_DIR="${NAS_CONFIG_DIR:-/var/lib/nas-test/repo}"
TEST_TIMEOUT="${NAS_TEST_TIMEOUT:-$(nas_vm_ordinary_wait_seconds)}"
AUTHENTIK_OUTPOST_PORT="${NAS_AUTHENTIK_OUTPOST_PORT:-9010}"
AUTHENTIK_OUTPOST_PID=""
AUTHENTIK_OUTPOST_LOG="/run/nas-authentik-vm-outpost.log"
BROWSER_PORT_FORWARD_PID=""
BROWSER_PORT_FORWARD_LOG="/run/nas-browser-port-forward.log"
authz_secret_dir=""

log() { printf '\n==> %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

stop_authentik_vm_outpost() {
  local cleanup_status=0
  if [[ -n "$AUTHENTIK_OUTPOST_PID" ]] && kill -0 "$AUTHENTIK_OUTPOST_PID" >/dev/null 2>&1; then
    if nas_vm_stop_process "$AUTHENTIK_OUTPOST_PID" "$(nas_vm_kill_after_seconds)"; then
      :
    else
      cleanup_status=$?
    fi
  fi
  AUTHENTIK_OUTPOST_PID=""
  if rm -f -- "$AUTHENTIK_OUTPOST_LOG"; then
    :
  else
    local remove_status=$?
    ((cleanup_status != 0)) || cleanup_status=$remove_status
  fi
  return "$cleanup_status"
}

stop_browser_port_forward() {
  local cleanup_status=0
  if [[ -n "$BROWSER_PORT_FORWARD_PID" ]] && kill -0 "$BROWSER_PORT_FORWARD_PID" >/dev/null 2>&1; then
    if nas_vm_stop_process "$BROWSER_PORT_FORWARD_PID" "$(nas_vm_kill_after_seconds)"; then
      :
    else
      cleanup_status=$?
    fi
  fi
  BROWSER_PORT_FORWARD_PID=""
  if rm -f -- "$BROWSER_PORT_FORWARD_LOG"; then
    :
  else
    local remove_status=$?
    ((cleanup_status != 0)) || cleanup_status=$remove_status
  fi
  return "$cleanup_status"
}

start_browser_port_forward() {
  local public_address public_port systemd_path systemd_root activate_path proxy_path
  if [[ ! "$AUTHENTIK_PUBLIC_HOST" =~ :([0-9]+)$ ]]; then
    return 0
  fi
  public_port="${BASH_REMATCH[1]}"
  [[ "$public_port" != 443 ]] || return 0
  # The VM maps the public test host back to its own HTTPS listener. Avoid
  # resolver races with DHCP-provided addresses; callers may override it.
  public_address="${NAS_BROWSER_HOST_ADDRESS:-127.0.0.1}"
  export NAS_BROWSER_HOST_ADDRESS="$public_address"
  systemd_path="$(command -v systemctl)"
  systemd_root="$(dirname "$(dirname "$(readlink -f "$systemd_path")")")"
  activate_path="$systemd_root/bin/systemd-socket-activate"
  proxy_path="$systemd_root/lib/systemd/systemd-socket-proxyd"
  [[ -x "$activate_path" ]] || fail "systemd-socket-activate is missing at $activate_path"
  [[ -x "$proxy_path" ]] || fail "systemd-socket-proxyd is missing at $proxy_path"
  rm -f -- "$BROWSER_PORT_FORWARD_LOG"
  # The browser flow can spend several minutes in Authentik between callback
  # requests. This process is test-owned and cleaned up explicitly, so do not
  # let the proxy's idle timeout remove the listener mid-flow.
  "$activate_path" --listen "$public_address:$public_port" \
    "$proxy_path" 127.0.0.1:443 >"$BROWSER_PORT_FORWARD_LOG" 2>&1 &
  BROWSER_PORT_FORWARD_PID=$!
  nas_vm_cleanup_add stop_browser_port_forward
  if ! timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "$TEST_TIMEOUT" bash -c \
    'until ss -tln | grep -Eq "'"$public_address"':'"$public_port"'[[:space:]]"; do sleep 1; done'; then
    cat "$BROWSER_PORT_FORWARD_LOG" >&2 || true
    fail "timed out waiting for the browser callback port $public_port"
  fi
  pass "browser callback port $public_address:$public_port forwards to guest HTTPS"
}

on_error() {
  local rc=$?
  printf '\nVM validation failed with status %s.\n' "$rc" >&2
  systemctl --failed --no-pager >&2 || true
  journalctl -b -n 250 --no-pager >&2 || true
  zpool status >&2 || true
  exit "$rc"
}
trap on_error ERR
nas_vm_cleanup_add stop_authentik_vm_outpost

require_commands() {
  local missing=() command
  for command in "$@"; do
    command -v "$command" >/dev/null 2>&1 || missing+=("$command")
  done
  ((${#missing[@]} == 0)) || fail "missing commands: ${missing[*]}"
}

wait_active() {
  local unit=$1
  if ! timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "$TEST_TIMEOUT" bash -c "until systemctl is-active --quiet '$unit'; do sleep 2; done"; then
    systemctl status "$unit" --no-pager >&2 || true
    fail "timed out waiting for $unit to become active"
  fi
}

wait_inactive() {
  local unit=$1
  if ! timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "$TEST_TIMEOUT" bash -c "until ! systemctl is-active --quiet '$unit'; do sleep 2; done"; then
    systemctl status "$unit" --no-pager >&2 || true
    fail "timed out waiting for $unit to become inactive"
  fi
}

wait_http() {
  local url=$1
  shift
  timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" "$TEST_TIMEOUT" bash -c \
    'until curl --fail --silent --show-error --connect-timeout 2 --max-time 10 "$@" >/dev/null; do sleep 2; done' \
    bash "$@" "$url"
}

http_code() {
  curl --silent --show-error --insecure --output /dev/null --write-out '%{http_code}' \
    --connect-timeout 3 --max-time 20 "$@"
}

assert_http_responsive() {
  local description=$1
  shift
  local code
  code="$(http_code "$@" || true)"
  case "$code" in
    200|201|202|204|301|302|303|307|308|400|401|403|404|405)
      pass "$description is responding (HTTP $code)"
      ;;
    *) fail "$description did not provide a usable HTTP response (${code:-none})" ;;
  esac
}

assert_no_502_authentik_redirect() {
  local path=$1 description=$2 response
  response="$(curl --silent --show-error --insecure --output /dev/null \
    --write-out '%{http_code} %{redirect_url}' \
    --connect-timeout 3 --max-time 20 \
    --resolve "$PUBLIC_HOST:443:127.0.0.1" "https://$PUBLIC_HOST$path" || true)"
  case "$response" in
    301\ https://"$PUBLIC_HOST"/identity/*|302\ https://"$PUBLIC_HOST"/identity/*|303\ https://"$PUBLIC_HOST"/identity/*|307\ https://"$PUBLIC_HOST"/identity/*|308\ https://"$PUBLIC_HOST"/identity/*|301\ https://"$AUTHENTIK_PUBLIC_HOST"/identity/*|302\ https://"$AUTHENTIK_PUBLIC_HOST"/identity/*|303\ https://"$AUTHENTIK_PUBLIC_HOST"/identity/*|307\ https://"$AUTHENTIK_PUBLIC_HOST"/identity/*|308\ https://"$AUTHENTIK_PUBLIC_HOST"/identity/*)
      pass "$description redirects to Authentik ($response)"
      ;;
    *) fail "$description returned an unavailable or non-Authentik response instead of redirecting to the configured Authentik origin ($response)" ;;
  esac
}

assert_blocked() {
  local path=$1 code
  code="$(http_code --resolve "$PUBLIC_HOST:443:127.0.0.1" "https://$PUBLIC_HOST$path")"
  case "$code" in
    301|302|303|307|308|401|403|404) pass "unauthenticated $path is blocked, hidden, or redirected ($code)" ;;
    *) fail "unauthenticated $path returned unexpected HTTP $code" ;;
  esac
}

assert_spoof_blocked() {
  local path=$1 code
  code="$(http_code --resolve "$PUBLIC_HOST:443:127.0.0.1" \
    -H 'Remote-User: akadmin' -H 'Remote-Groups: nas_admin,nas_allow_files,nas_allow_ai' \
    -H 'X-authentik-username: akadmin' -H 'X-authentik-groups: nas_admin' \
    "https://$PUBLIC_HOST$path")"
  case "$code" in
    301|302|303|307|308|401|403|404) pass "spoofed identity headers do not bypass $path ($code)" ;;
    *) fail "spoofed identity headers bypassed or unexpectedly reached $path (HTTP $code)" ;;
  esac
}

setup_administrator() {
  local administrator
  administrator="nas-bootstrap"
  if [[ -r /var/lib/nas-setup/local-administrator.json ]]; then
    administrator="$(jq -er '.username | strings' /var/lib/nas-setup/local-administrator.json)"
  fi
  printf '%s\n' "$administrator"
}

run_as_admin() {
  local administrator home
  administrator="$(setup_administrator)"
  home="$(getent passwd "$administrator" | awk -F: 'NR == 1 { print $6; exit }')"
  [[ -n "$home" ]] || fail "configured local administrator is unavailable: $administrator"
  runuser -u "$administrator" -- env HOME="$home" PATH="$PATH" "$@"
}

activate_secrets() {
  run_as_admin_with_stdin "$(nas_vm_timeout_value secretActivation)" nas-secrets activate-stdin
}

run_as_admin_with_stdin() {
  local timeout_seconds=$1 administrator home
  shift
  administrator="$(setup_administrator)"
  home="$(getent passwd "$administrator" | awk -F: 'NR == 1 { print $6; exit }')"
  [[ -n "$home" ]] || fail "configured local administrator is unavailable: $administrator"
  nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" \
    runuser -u "$administrator" -- env HOME="$home" PATH="$PATH" \
      timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" "$timeout_seconds" "$@"
}

authentik_api() {
  local method=$1 path=$2 body=${3:-}
  if [[ -n "$body" ]]; then
    curl --fail --silent --show-error --max-time 30 -X "$method" -H "Authorization: Bearer $AUTHENTIK_BOOTSTRAP_TOKEN" -H 'Content-Type: application/json' --data-binary "$body" "http://127.0.0.1:9000/identity/api/v3/$path"
  else
    curl --fail --silent --show-error --max-time 30 -X "$method" -H "Authorization: Bearer $AUTHENTIK_BOOTSTRAP_TOKEN" "http://127.0.0.1:9000/identity/api/v3/$path"
  fi
}

verify_bootstrap_authentik_proxy() {
  local provider_id setup_provider_id outpost_id code provider_response application_response group_response outpost_response
  provider_response="$(authentik_api GET 'providers/proxy/?page_size=100')" || fail 'Authentik provider API was not ready'
  provider_id="$(printf '%s' "$provider_response" | jq -er '.results[] | select(.name == "NAS Portal") | .pk')" || \
    fail 'Authentik bootstrap portal provider was not present'
  printf '%s' "$provider_response" | jq -e --arg provider "$provider_id" --arg host "https://$AUTHENTIK_PUBLIC_HOST" \
    '.results[] | select((.pk | tostring) == $provider and .external_host == $host and .mode == "forward_single")' >/dev/null || \
    fail 'Authentik bootstrap portal provider has unexpected settings'
  application_response="$(authentik_api GET 'core/applications/?page_size=100')" || fail 'Authentik application API was not ready'
  printf '%s' "$application_response" | jq -e --arg provider "$provider_id" --arg host "https://$AUTHENTIK_PUBLIC_HOST" \
    '.results[] | select(.slug == "nas-portal" and (.provider | tostring) == $provider and .meta_launch_url == $host)' >/dev/null || \
    fail 'Authentik bootstrap portal application was not present'
  setup_provider_id="$(printf '%s' "$provider_response" | jq -er '.results[] | select(.name == "NAS Setup") | .pk')" || \
    fail 'Authentik bootstrap setup provider was not present'
  printf '%s' "$provider_response" | jq -e --arg provider "$setup_provider_id" --arg host "https://$AUTHENTIK_PUBLIC_HOST/setup/" \
    '.results[] | select((.pk | tostring) == $provider and .external_host == $host and .mode == "forward_single")' >/dev/null || \
    fail 'Authentik bootstrap setup provider has unexpected settings'
  printf '%s' "$application_response" | jq -e --arg provider "$setup_provider_id" --arg host "https://$AUTHENTIK_PUBLIC_HOST/setup/" \
    '.results[] | select(.slug == "nas-setup" and (.provider | tostring) == $provider and .meta_launch_url == $host)' >/dev/null || \
    fail 'Authentik bootstrap setup application was not provider-backed'
  group_response="$(authentik_api GET 'core/groups/?include_users=true&page_size=100')" || fail 'Authentik group API was not ready'
  printf '%s' "$group_response" | jq -e \
    '.results[] | select(.name == "nas_admin") | (.users_obj // .users // []) | any(.username == "akadmin")' >/dev/null || \
    fail 'Authentik bootstrap administrator membership was not present'
  outpost_response="$(authentik_api GET 'outposts/instances/?page_size=100')" || fail 'Authentik outpost API was not ready'
  outpost_id="$(printf '%s' "$outpost_response" | jq -er '.results[] | select(.managed == "goauthentik.io/outposts/embedded") | .pk')" || \
    fail 'Authentik embedded outpost was not present'
  outpost_response="$(authentik_api GET "outposts/instances/$outpost_id/")" || fail 'Authentik embedded outpost API was not ready'
  printf '%s' "$outpost_response" | jq -e --arg provider "$provider_id" \
    '(.providers | map(tostring) | index($provider)) != null' >/dev/null || \
    fail 'Authentik embedded outpost was not assigned the portal provider'
  printf '%s' "$outpost_response" | jq -e --arg provider "$setup_provider_id" \
    '(.providers | map(tostring) | index($provider)) != null' >/dev/null || \
    fail 'Authentik embedded outpost was not assigned the setup provider'
  printf '%s' "$outpost_response" | jq -e \
    --arg host "https://$AUTHENTIK_PUBLIC_HOST/identity/" \
    --arg browser_host "https://$AUTHENTIK_PUBLIC_HOST/identity/" \
    '.config.authentik_host == $host and .config.authentik_host_browser == $browser_host' >/dev/null || \
    fail 'Authentik embedded outpost has unexpected host settings'
  code="$(http_code -H "Host: $PUBLIC_HOST" "http://127.0.0.1:$AUTHENTIK_OUTPOST_PORT/outpost.goauthentik.io/ping" || true)"
  [[ "$code" == 204 ]] || fail "Authentik bootstrap proxy outpost did not become reachable (HTTP ${code:-none})"
  pass 'bootstrap Authentik portal provider, application, and outpost assignment are ready'
}

require_commands \
  curl findmnt firewall-cmd getent git ip jq keepassxc-cli nas-alert nas-cockpit-api nas-managed-services-control \
  nas-identity-sync nas-operation-run nas-preflight nas-secrets nas-setup nas-update nas-ups-init-password \
  nas-zfs-create-encrypted-dataset nas-zfs-export-recovery-key nas-zfs-lock \
  nas-zfs-mount-check nas-zfs-unlock proxy python3 readlink ss systemctl zfs zpool

nas-managed-services-control status >/dev/null
pass "nas-managed-services-control status reports the V2 authority"
nas-managed-services-control document >/dev/null
pass "nas-managed-services-control document returns the editable YAML authority"

log "Locked-state and configuration checks"
! systemctl is-active --quiet cockpit.socket || fail "stock Cockpit socket must stay inactive while locked"
wait_active nas-cockpit-sso.service
ss -tln | grep -Eq '127\.0\.0\.1:9092[[:space:]]' || fail "Cockpit SSO session is not loopback-only while locked"
! ss -tln | grep -Eq '(0\.0\.0\.0|\[::\]):9092[[:space:]]' || fail "Cockpit listener is exposed while locked"
wait_active nas-first-start.service
systemctl show nas-first-start.service --property=RemainAfterExit --value | grep -qx yes
jq -e '.schemaVersion == 2 and (.status | type == "string")' /var/lib/nas-first-start/status.json >/dev/null
systemctl restart nas-first-start.service
wait_active nas-first-start.service
jq -e '.schemaVersion == 2 and (.status | type == "string")' /var/lib/nas-first-start/status.json >/dev/null
pass "first-start oneshot remains active and republishes readiness across restart"
[[ ! -e /run/nas-secrets/ready ]] || fail "runtime secrets were unexpectedly active at boot"
wait_active caddy.service
! systemctl is-active --quiet copyparty.service || fail "CopyParty must remain stopped while locked"
wait_active authentik.service
[[ "$(systemctl show nas-identity-bootstrap.service --property=NRestarts --value)" == 0 ]] || \
  fail "identity bootstrap retried before Authentik's default flows were ready"
wait_active nas-authentik-proxy-outpost.service
wait_http http://127.0.0.1:9000/identity/-/health/ready/
AUTHENTIK_BOOTSTRAP_TOKEN="$(< /run/nas-authentik/api-token)"
verify_bootstrap_authentik_proxy
[[ -f /var/lib/nas-bootstrap/authentik/environment ]] || fail "first-boot Authentik environment is missing"
[[ -f /var/lib/nas-bootstrap/authentik/api-token ]] || fail "first-boot Authentik API token is missing"
[[ "$(readlink -f /run/nas-authentik/environment)" == "/var/lib/nas-bootstrap/authentik/environment" ]] || \
  fail "Authentik did not select the first-boot environment"
wait_http http://127.0.0.1:9000/identity/-/health/ready/
assert_no_502_authentik_redirect / "locked base route"
assert_no_502_authentik_redirect /console "locked console route"
start_browser_port_forward
bootstrap_authz_secret_dir=$(mktemp -d /run/nas-bootstrap-authz-test.XXXXXX)
cleanup_bootstrap_authz_secrets() {
  [[ -n "${bootstrap_authz_secret_dir:-}" ]] || return 0
  rm -rf -- "$bootstrap_authz_secret_dir"
}
nas_vm_cleanup_add cleanup_bootstrap_authz_secrets
chmod 0700 "$bootstrap_authz_secret_dir"
printf '%s\n' 'nas-admin-first-boot' > "$bootstrap_authz_secret_dir/akadmin"
chmod 0600 "$bootstrap_authz_secret_dir/akadmin"
timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
  "$(nas_vm_timeout_value browserAuthorization)" python3 /var/lib/nas-test/repo/tests/browser/authz.py \
  --origin "https://$AUTHENTIK_PUBLIC_HOST" \
  --bootstrap-only \
  --bootstrap-password-file "$bootstrap_authz_secret_dir/akadmin"
cleanup_bootstrap_authz_secrets
bootstrap_authz_secret_dir=""
pass "locked first boot runs isolated Authentik and routes browser access through the public Authentik host"

[[ -d "$CONFIG_DIR" ]] || fail "test configuration checkout is missing: $CONFIG_DIR"
json="$(nas-update --status --json)"
jq -e '.configurationDir and .currentSystem' <<<"$json" >/dev/null
pass "nas-update status reports the protected checkout"

nas-operation-run --action vm-operation-run-smoke --class runtime -- true
pass "shared operation runner executes an installed child under coordinator ownership"

# AI configuration/control executables are source-contract qualified here even when the optional
# coding-agent feature is not enabled in this VM profile.
if command -v nas-ai-config >/dev/null 2>&1; then
  nas-ai-config --help >/dev/null
  pass "nas-ai-config CLI is installed and starts"
fi
if command -v nas-code-agent >/dev/null 2>&1; then
  nas-code-agent --help >/dev/null
  pass "nas-code-agent CLI is installed and starts"
fi
if command -v nas-code >/dev/null 2>&1; then
  command -v nas-code >/dev/null
  pass "nas-code optional launcher is installed when codingAgent is enabled"
fi

log "Run the complete first-time setup CLI"
for _ in $(seq 1 60); do
  [[ -b "$ZFS_DEVICE" ]] && break
  sleep 1
done
[[ -b "$ZFS_DEVICE" ]] || fail "ZFS test disk did not appear: $ZFS_DEVICE"
install -d -m 0700 -o nas-bootstrap -g users /var/lib/nas-test/setup
printf '%s\n' 'alice-vm-password' >/var/lib/nas-test/setup/alice.password
printf '%s\n' 'operator-vm-password' >/var/lib/nas-test/setup/operator.password
printf '%s\n' 'baseline-vm-password' >/var/lib/nas-test/setup/baseline.password
chown nas-bootstrap:users /var/lib/nas-test/setup/*.password
chmod 0600 /var/lib/nas-test/setup/*.password
cat >/var/lib/nas-test/setup/first-run.json <<EOFSETUP
{
  "schemaVersion": 2,
  "storage": {
    "createPool": true,
    "device": "$ZFS_DEVICE",
    "wipeDevice": true
  },
  "accounts": [
    {
      "username": "operator",
      "name": "Second NAS Administrator",
      "email": "operator@nas.local",
      "groups": ["nas_admin"],
      "passwordFile": "/var/lib/nas-test/setup/operator.password"
    },
    {
      "username": "alice",
      "name": "Alice Example",
      "email": "alice@nas.local",
      "groups": ["nas_users"],
      "passwordFile": "/var/lib/nas-test/setup/alice.password"
    },
    {
      "username": "baseline",
      "name": "Baseline User",
      "email": "baseline@nas.local",
      "groups": ["nas_users"],
      "passwordFile": "/var/lib/nas-test/setup/baseline.password"
    },
    {
      "username": "guest",
      "name": "Guest User",
      "email": "guest@nas.local",
      "groups": ["nas_guests"]
    }
  ],
  "runPreflight": true
}
EOFSETUP
chown nas-bootstrap:users /var/lib/nas-test/setup/first-run.json
chmod 0600 /var/lib/nas-test/setup/first-run.json
run_as_admin nas-setup validate-config /var/lib/nas-test/setup/first-run.json | jq -e '.accounts | length == 4'
nas_setup_path="$(readlink -f "$(command -v nas-setup)")"
[[ $nas_setup_path == /nix/store/*-nas-setup/bin/nas-setup ]] || fail "nas-setup resolves to unexpected package: $nas_setup_path"
plan_json="$(run_as_admin nas-setup prepare-first-start --config /var/lib/nas-test/setup/first-run.json)"
plan_digest="$(jq -er '.planDigest | select(test("^[0-9a-f]{64}$"))' <<<"$plan_json")"
stale_digest="$(printf '0%.0s' {1..64})"
if run_as_admin nas-setup first-run --config /var/lib/nas-test/setup/first-run.json \
  --confirm-plan-digest "$stale_digest" >/tmp/nas-stale-plan.out 2>/tmp/nas-stale-plan.err; then
  fail "first-run accepted a stale plan digest"
fi
if ! grep -qi 'plan.*changed\|digest' /tmp/nas-stale-plan.err; then
  printf '%s\n' '--- stale plan stdout ---' >&2
  cat /tmp/nas-stale-plan.out >&2
  printf '%s\n' '--- stale plan stderr ---' >&2
  cat /tmp/nas-stale-plan.err >&2
  fail "stale plan digest failure was not diagnostic"
fi
pass "first-run rejects a stale plan digest before mutation"
run_as_admin_with_stdin "$(nas_vm_timeout_value firstRun)" nas-setup first-run \
  --config /var/lib/nas-test/setup/first-run.json \
  --keepass-password-stdin \
  --confirm-plan-digest "$plan_digest" \
  --confirm-storage-device "$ZFS_DEVICE" \
  --allow-destructive-storage >/tmp/nas-first-run.json
if ! jq -e '
  .storage.createdPool == true and
  .storage.createdDataset == true and
  (.accounts.created | sort) == ["alice", "baseline", "guest", "operator"] and
  (.identity.administrators | index("operator")) != null
' /tmp/nas-first-run.json >/dev/null; then
  printf '%s\n' '--- first-run report ---' >&2
  jq . /tmp/nas-first-run.json >&2 || cat /tmp/nas-first-run.json >&2
  fail "nas-setup first-run report did not contain the expected storage, account, and administrator state"
fi
pass "nas-setup first-run created the expected storage and accounts"
chown operator:users /var/lib/nas-test/setup
chown operator:users /var/lib/nas-test/setup/first-run.json
run_as_admin nas-setup prepare-first-start --config /var/lib/nas-test/setup/first-run.json \
  >/tmp/nas-first-start-status.json
if ! jq -e '.status == "complete" and .configPath == "/var/lib/nas-test/setup/first-run.json"' \
  /tmp/nas-first-start-status.json >/dev/null; then
  printf '%s\n' '--- first-start status ---' >&2
  jq . /tmp/nas-first-start-status.json >&2 || cat /tmp/nas-first-start-status.json >&2
  fail "first-start status did not report complete for the configured plan"
fi
if ! nas-setup status | jq -e '
  .runtimeSecretsActive == true and
  .poolPresent == true and
  .datasetPresent == true and
  .setupState
' >/dev/null; then
  nas-setup status >&2 || true
  fail "nas-setup status did not report an active completed setup"
fi
if [[ ! -d /tank/shares/users/alice || ! -d /tank/shares/users/operator ]]; then
  find /tank/shares/users -maxdepth 1 -mindepth 1 -printf '%M %u:%g %p\n' >&2 || true
  fail "first-run did not create both expected personal share directories"
fi
if [[ "$(stat -c '%a:%U:%G' /tank/shares/users/alice)" != "2770:copyparty:copyparty" ]]; then
  stat -c '%a:%U:%G %n' /tank/shares/users/alice >&2 || true
  fail "Alice's personal share directory has unexpected ownership or mode"
fi
findmnt -n -o FSTYPE,SOURCE,TARGET /tank | grep -q '^zfs tank/nas /tank$'
pass "nas-setup created storage, KeePass secrets, accounts, shares, and activated the stack"

log "Adversarial command, SQL-like input, and HTTP validation"
rm -f /tmp/nas-command-injection-marker
# shellcheck disable=SC2016
if nas-cockpit-api managed-service 'ai-workspace;touch${IFS}/tmp/nas-command-injection-marker' always >/tmp/nas-bad-feature.out 2>/tmp/nas-bad-feature.err; then
  fail "Cockpit API accepted a command-injection-shaped service identifier"
fi
[[ ! -e /tmp/nas-command-injection-marker ]] || fail "service identifier escaped into shell execution"
if nas-setup account disable "' OR '1'='1" >/tmp/nas-bad-account.out 2>/tmp/nas-bad-account.err; then
  fail "account command accepted an SQL-injection-shaped username"
fi
cat >/tmp/nas-bad-path-config.json <<'EOF_BAD_CONFIG'
{"schemaVersion":2,"storage":{"createPool":true,"devices":["../../dev/vdb"]}}
EOF_BAD_CONFIG
if nas-setup validate-config /tmp/nas-bad-path-config.json >/tmp/nas-bad-path.out 2>/tmp/nas-bad-path.err; then
  fail "setup accepted a traversal-shaped storage device"
fi
wait_active nas-alert-router.service
code="$(curl --silent --output /tmp/nas-alert-malformed.json --write-out '%{http_code}' \
  --header 'Content-Type: application/json' --data-binary '{' http://127.0.0.1:9093/api/v2/alerts)"
[[ "$code" == 400 ]] || fail "alert router malformed JSON returned HTTP $code instead of 400"
! grep -q 'Traceback' /tmp/nas-alert-malformed.json || fail "alert router leaked a traceback for malformed JSON"
transfer_code="$(curl --silent --output /tmp/nas-alert-transfer.json --write-out '%{http_code}' \
  --header 'Transfer-Encoding: chunked' --header 'Content-Type: application/json' \
  --data-binary '[]' http://127.0.0.1:9093/api/v2/alerts || true)"
[[ "$transfer_code" == 400 ]] || fail "alert router accepted ambiguous transfer encoding (HTTP $transfer_code)"
pass "hostile identifiers, traversal, and malformed alert requests fail closed"

log "Cockpit ZFS rollback wrapper"
rollback_wrapper="$(find /nix/store -maxdepth 3 -type f -path '*/bin/zfs' \
  -exec grep -Il 'Created post-restore marker' {} + 2>/dev/null | head -n1)"
[[ -n "$rollback_wrapper" ]] || fail "Cockpit ZFS rollback wrapper was not found in the closure"
rollback_dataset=tank/nas/qemu-rollback
zfs destroy -r "$rollback_dataset" >/dev/null 2>&1 || true
zfs create -o mountpoint=/tank/qemu-rollback "$rollback_dataset"
printf 'before\n' >/tank/qemu-rollback/value.txt
zfs snapshot "$rollback_dataset@before"
printf 'after\n' >/tank/qemu-rollback/value.txt
"$rollback_wrapper" rollback -r "$rollback_dataset@before" >/tmp/nas-zfs-wrapper.log
grep -qx 'before' /tank/qemu-rollback/value.txt
marker="$(zfs list -H -t snapshot -o name -r "$rollback_dataset" | grep '@restored-before-' | head -n1)"
[[ -n "$marker" ]] || fail "Cockpit ZFS wrapper did not create a post-restore marker"
[[ "$(zfs get -H -o value org.nixos:restore-source "$marker")" == "$rollback_dataset@before" ]] || \
  fail "post-restore marker does not record its source snapshot"
zfs destroy -r "$rollback_dataset"
pass "Cockpit ZFS rollback wrapper restores data and creates a source marker"

! nas-zfs-lock >/tmp/nas-zfs-lock-disabled.log 2>&1 || fail "nas-zfs-lock succeeded with encryption disabled"
grep -q 'zfsEncryption.enable is false' /tmp/nas-zfs-lock-disabled.log
! nas-zfs-unlock >/tmp/nas-zfs-unlock-disabled.log 2>&1 || fail "nas-zfs-unlock succeeded with encryption disabled"
grep -q 'zfsEncryption.enable is false' /tmp/nas-zfs-unlock-disabled.log
! nas-zfs-create-encrypted-dataset >/tmp/nas-zfs-create-disabled.log 2>&1 || fail "encrypted-dataset creation succeeded while disabled"
grep -q 'Enable nas.zfsEncryption.enable' /tmp/nas-zfs-create-disabled.log
! nas-ups-init-password >/tmp/nas-ups-disabled.log 2>&1 || fail "UPS password initialization succeeded while UPS support was disabled"
grep -q 'Enable nas.power.ups' /tmp/nas-ups-disabled.log
pass "disabled ZFS encryption and UPS tools fail early without unreachable code"

log "Verify first-run protected services and account population"
[[ -f /run/nas-secrets/ready ]] || fail "first-run setup did not commit runtime secrets"
for unit in \
  nas-protected-services.target postgresql.service authentik-worker.service \
  authentik.service copyparty.service \
  nas-on-demand-gate.service caddy.service; do
  wait_active "$unit"
done
wait_active nas-v2-timer-identity-sync-0.timer
[[ -S /run/copyparty/http.sock ]] || fail "CopyParty Unix socket is missing"
wait_http http://127.0.0.1:9000/identity/-/health/ready/
curl --fail --silent --show-error --max-time 20 \
  --unix-socket /run/copyparty/http.sock http://localhost/ >/dev/null
nas-identity-sync status | jq -e '
  (.users | index("alice")) != null and
  (.users | index("guest")) != null and
  (.administrators | index("operator")) != null
' >/dev/null
nas-identity-sync capabilities | jq -e '
  .users[] |
  select(.id == "alice") |
  .capabilities == {} and
  .assignedApplicationCapabilities == []
' >/dev/null
printf '%s\n' 'alice-updated-password' |
  run_as_admin nas-setup account apply --username alice --password-stdin \
    >/tmp/nas-account-password-update.json
jq -e '.account.updated == ["alice"]' /tmp/nas-account-password-update.json >/dev/null
run_as_admin nas-setup account apply --username alice \
  --name '<img src=x onerror=document.body.dataset.nasXss=1>' \
  >/tmp/nas-account-xss-name.json
jq -e '.account.updated == ["alice"]' /tmp/nas-account-xss-name.json >/dev/null
nas-identity-sync export-account alice | jq -e '
  .active == true and
  (.groups | index("nas_users")) != null and
  (.groups | index("nas_allow_files")) == null and
  (.groups | index("nas_allow_vault")) == null and
  (.groups | index("nas_allow_syncthing")) == null
' >/dev/null
printf '%s\n' 'temporary-password' |
  run_as_admin nas-setup account apply \
    --username temporary \
    --name 'Temporary User' \
    --email temporary@nas.local \
    --group nas_users \
    --password-stdin >/tmp/nas-account-add.json
jq -e '.account.created == ["temporary"]' /tmp/nas-account-add.json >/dev/null
run_as_admin nas-setup account disable temporary >/tmp/nas-account-disable.json
jq -e '.updated == ["temporary"]' /tmp/nas-account-disable.json >/dev/null
nas-identity-sync export-account temporary | jq -e '
  .active == false and
  (.groups | index("nas_disabled")) != null and
  (.groups | index("nas_admin")) == null and
  (.groups | index("nas_users")) == null
' >/dev/null
pass "core services, account apply/disable CLI, and CopyParty backend are healthy"

log "Anonymous read-only TFTP behavior"
[[ -d /tank/shares/tftp ]] || fail "ZFS-backed TFTP directory was not created"
printf 'nixos-nas-qemu-tftp\n' >/tank/shares/tftp/qemu-tftp.txt
chown copyparty:copyparty /tank/shares/tftp/qemu-tftp.txt
chmod 0660 /tank/shares/tftp/qemu-tftp.txt
timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" "$TEST_TIMEOUT" bash -c \
  "until ss -lun | grep -Eq '[:.]3969[[:space:]]'; do sleep 2; done"
python3 - <<'PYTFTP'
import socket
import struct
from pathlib import Path

SERVER = ("127.0.0.1", 3969)
REMOTE = "tftp/qemu-tftp.txt"
EXPECTED = b"nixos-nas-qemu-tftp\n"


def packet(opcode: int, name: str) -> bytes:
    return struct.pack("!H", opcode) + name.encode() + b"\0octet\0"


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(10)
sock.sendto(packet(1, REMOTE), SERVER)  # RRQ
received = bytearray()
expected_block = 1
while True:
    response, peer = sock.recvfrom(65535)
    opcode = struct.unpack("!H", response[:2])[0]
    if opcode == 5:
        code = struct.unpack("!H", response[2:4])[0]
        message = response[4:-1].decode("utf-8", "replace")
        raise SystemExit(f"TFTP read failed ({code}): {message}")
    if opcode != 3 or len(response) < 4:
        raise SystemExit(f"unexpected TFTP read packet opcode={opcode}")
    block = struct.unpack("!H", response[2:4])[0]
    if block != expected_block:
        raise SystemExit(f"unexpected TFTP block {block}, wanted {expected_block}")
    payload = response[4:]
    received.extend(payload)
    sock.sendto(struct.pack("!HH", 4, block), peer)
    if len(payload) < 512:
        break
    expected_block = (expected_block + 1) & 0xFFFF

if bytes(received) != EXPECTED:
    raise SystemExit(f"TFTP payload mismatch: {bytes(received)!r}")

upload = "tftp/qemu-upload-must-fail.txt"
write_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
write_sock.settimeout(3)
write_sock.sendto(packet(2, upload), SERVER)
try:
    response, _peer = write_sock.recvfrom(65535)
except TimeoutError:
    # CopyParty's anonymous read-only TFTP mode rejects writes by withholding
    # a transfer response; the absence of a created file is the authority.
    pass
else:
    opcode = struct.unpack("!H", response[:2])[0]
    if opcode != 5:
        raise SystemExit(f"read-only TFTP accepted a write request (opcode={opcode})")
write_sock.close()
if Path("/tank/shares/tftp/qemu-upload-must-fail.txt").exists():
    raise SystemExit("read-only TFTP created the rejected upload")
PYTFTP
pass "TFTP serves anonymous reads and rejects writes in read-only mode"

log "Authentik API, identity policy, and proxy authorization"
unauth_code="$(http_code http://127.0.0.1:9000/identity/api/v3/core/users/)"
case "$unauth_code" in 401|403) : ;; *) fail "Authentik API without a token returned $unauth_code" ;; esac
token="$(cat /run/nas-secrets/authentik/api-token)"
auth_code="$(http_code -H "Authorization: Bearer $token" http://127.0.0.1:9000/identity/api/v3/core/users/)"
[[ "$auth_code" == 200 ]] || fail "Authentik API token returned HTTP $auth_code"

nas-identity-sync status | jq -e \
  '.identityProvider == "Authentik" and .shareAuthority == "CopyParty" and (.administrators | length > 0)' >/dev/null
capabilities_json="$(nas-identity-sync capabilities)"
jq -e '.identityProvider == "Authentik" and (.users | length > 0)' <<<"$capabilities_json" >/dev/null
jq -e '[.users[] | select(.administrator) | .capabilities[] | .allowed] | length > 0 and all' \
  <<<"$capabilities_json" >/dev/null

gate_deny="$(http_code --unix-socket /run/nas-on-demand/gate.sock \
  -H 'Remote-User: ordinary-user' -H 'Remote-Groups: nas_users' \
  'http://localhost/authorize?scope=files')"
[[ "$gate_deny" == 403 ]] || fail "default-deny capability gate returned HTTP $gate_deny"
gate_allow="$(http_code --unix-socket /run/nas-on-demand/gate.sock \
  -H 'Remote-User: allowed-user' -H 'Remote-Groups: nas_users,nas_allow_files' \
  'http://localhost/authorize?scope=files')"
case "$gate_allow" in 200|204) : ;; *) fail "explicit files capability returned HTTP $gate_allow" ;; esac
gate_admin="$(http_code --unix-socket /run/nas-on-demand/gate.sock \
  -H 'Remote-User: akadmin' -H 'Remote-Groups: nas_admin' \
  'http://localhost/authorize?scope=admin')"
case "$gate_admin" in 200|204) : ;; *) fail "administrator-only gate returned HTTP $gate_admin" ;; esac
python3 - <<'PYHOSTILEGATE'
import socket

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect("/run/nas-on-demand/gate.sock")
sock.sendall(
    b"GET /authorize?scope=admin HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Remote-User: attacker\r\n"
    b"Remote-Groups: nas_users,\tnas_admin\r\n"
    b"Connection: close\r\n\r\n"
)
response = b""
while True:
    chunk = sock.recv(65536)
    if not chunk:
        break
    response += chunk
sock.close()
first = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
parts = first.split()
if len(parts) < 2 or parts[1] not in {"400", "401", "403", "503"}:
    raise SystemExit(f"control-character group header was not rejected fail-closed: {first!r}")
PYHOSTILEGATE
pass "malformed trusted identity headers remain fail-closed inside the installed gate"
nas-managed-services-control set ai-runtime off >/dev/null
wait_inactive nas-llama-swap.service

backend_admin="$(http_code --unix-socket /run/copyparty/http.sock \
  -H 'Remote-User: akadmin' -H 'Remote-Groups: nas_admin' \
  http://localhost/shares/admin/)"
case "$backend_admin" in 200|301|302|303|307|308) : ;; *) fail "trusted CopyParty administrator identity returned HTTP $backend_admin" ;; esac

assert_blocked /shares/
assert_spoof_blocked /shares/
assert_blocked /shares/admin/
assert_spoof_blocked /console/
assert_blocked /ai/
assert_spoof_blocked /ai/
assert_blocked /syncthing/
assert_blocked /vault/admin
assert_blocked /metrics/
assert_blocked /alerts/

# V2 routes must begin their unauthenticated flow at Authentik, rather than
# falling through to the launcher after the flow completes.
assert_no_502_authentik_redirect /console/ "managed Cockpit route"
assert_no_502_authentik_redirect /shares/ "managed application route"

identity_code="$(http_code --resolve "$PUBLIC_HOST:443:127.0.0.1" "https://$PUBLIC_HOST/identity/")"
case "$identity_code" in 200|301|302|303|307|308) : ;; *) fail "public Authentik login route returned $identity_code" ;; esac

caddy_exec="$(systemctl show caddy.service --property=ExecStart --value)"
caddy_config="$(sed -nE 's/.*--config[= ]([^ ;}]+).*/\1/p' <<<"$caddy_exec" | head -n1)"
[[ -n "$caddy_config" && -r "$caddy_config" ]] || fail "could not locate generated Caddy configuration"
grep -q 'request_header -Remote-User' "$caddy_config"
grep -q 'request_header -X-Authentik-Username' "$caddy_config"
pass "Authentik API and fail-closed proxy checks passed"
log "Authentication dependency outage stays fail-closed"
systemctl stop authentik.service
wait_inactive authentik.service
auth_down_code="$(http_code --resolve "$PUBLIC_HOST:443:127.0.0.1" \
  -H 'Remote-User: akadmin' -H 'Remote-Groups: nas_admin,nas_allow_files' \
  "https://$PUBLIC_HOST/shares/" || true)"
case "$auth_down_code" in
  200|201|202|204) fail "protected route became reachable while Authentik was unavailable" ;;
  *) : ;;
esac
systemctl start authentik.service
wait_active authentik.service
systemctl start nas-protected-services.target
wait_active nas-protected-services.target
wait_active caddy.service
wait_http http://127.0.0.1:9000/identity/-/health/live/
pass "protected proxy routes fail closed and recover after Authentik outage"
proxy_headers="$(curl --silent --show-error --insecure --dump-header - --output /dev/null \
  --resolve "$PUBLIC_HOST:443:127.0.0.1" "https://$PUBLIC_HOST/")"
printf '%s\n' "$proxy_headers" | grep -Eiq '^X-Content-Type-Options:[[:space:]]*nosniff[[:space:]]*$' || fail "proxy is missing nosniff header"
printf '%s\n' "$proxy_headers" | grep -Eiq '^Referrer-Policy:[[:space:]]*no-referrer[[:space:]]*$' || fail "proxy is missing no-referrer policy"
printf '%s\n' "$proxy_headers" | grep -Eiq '^Permissions-Policy:[[:space:]]*camera=\(\), microphone=\(\), geolocation=\(\)[[:space:]]*$' || fail "proxy is missing restricted permissions policy"
printf '%s\n' "$proxy_headers" | grep -Eiq '^Server:' && fail "proxy exposed a Server response header"
pass "proxy response hardening headers are present and server identity is suppressed"

log "Firewall fail-closed behavior from an independent untrusted namespace"
[[ "$(firewall-cmd --get-default-zone)" == drop ]] || fail "firewalld default zone is not fail-closed drop"
trusted_zone="${NAS_TEST_FIREWALL_ZONE:-nas-lan}"
firewall-cmd --get-active-zones | grep -q "^${trusted_zone}$" || fail "trusted NAS firewall zone is not active"
for service in ssh http https mdns; do
  firewall-cmd --zone="$trusted_zone" --query-service="$service" >/dev/null || fail "trusted zone is missing $service"
done

ip netns del nas-untrusted-test >/dev/null 2>&1 || true
ip link del nust-host >/dev/null 2>&1 || true
ip netns add nas-untrusted-test
ip link add nust-host type veth peer name nust-peer
ip link set nust-peer netns nas-untrusted-test
ip addr add 198.18.0.1/30 dev nust-host
ip link set nust-host up
ip netns exec nas-untrusted-test ip link set lo up
ip netns exec nas-untrusted-test ip addr add 198.18.0.2/30 dev nust-peer
ip netns exec nas-untrusted-test ip link set nust-peer up
for port in 22 80 443 9092 22000; do
  if ip netns exec nas-untrusted-test python3 -c \
    'import socket,sys; s=socket.socket(); s.settimeout(1.0); raise SystemExit(0 if s.connect_ex(("198.18.0.1", int(sys.argv[1]))) == 0 else 1)' \
    "$port"; then
    fail "untrusted namespace reached protected TCP port $port"
  fi
done
ip netns del nas-untrusted-test
ip link del nust-host >/dev/null 2>&1 || true
pass "untrusted interface cannot reach SSH, HTTP(S), Cockpit, or Syncthing while trusted-zone services remain available"

log "Browser-level authorization and deterministic bundle probes"
# The persistent wrapper keeps mutable local users across generations. Seed
# the disposable fixture's Authentik administrator credential so the Cockpit
# OAuth browser flow remains deterministic after the installed OS is updated.
printf '%s\n' 'admin:admin-vm-password' | chpasswd
authz_secret_dir=$(mktemp -d /run/nas-authz-test.XXXXXX)
cleanup_authz_secrets() {
  [[ -n "$authz_secret_dir" ]] || return 0
  rm -rf -- "$authz_secret_dir"
}
nas_vm_cleanup_add cleanup_authz_secrets
chmod 0700 "$authz_secret_dir"
printf '%s\n' operator-vm-password > "$authz_secret_dir/operator"
printf '%s\n' admin-vm-password > "$authz_secret_dir/admin"
printf '%s\n' alice-updated-password > "$authz_secret_dir/alice"
printf '%s\n' baseline-vm-password > "$authz_secret_dir/baseline"
chmod 0600 "$authz_secret_dir"/*
timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
  "$(nas_vm_timeout_value browserAuthorization)" python3 /var/lib/nas-test/repo/tests/browser/authz.py \
   --origin "https://$AUTHENTIK_PUBLIC_HOST" \
   --cockpit-password-file "$authz_secret_dir/admin" \
  --operator-password-file "$authz_secret_dir/operator" \
  --alice-password-file "$authz_secret_dir/alice" \
  --baseline-password-file "$authz_secret_dir/baseline"
cleanup_authz_secrets
authz_secret_dir=""
pass "Browser authorization and Authentik user-settings flow"

# Deterministic bundle probes serve the built distribution over loopback with a
# stub base1/cockpit.js so the React app mounts without the Cockpit shell, then
# replay hostile backend strings and viewport/text-scale combinations. The VM
# owns the committed distribution copy at /var/lib/nas-test/repo/cockpit/dist.
timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
  "$(nas_vm_timeout_value deterministicBundle)" python3 /var/lib/nas-test/repo/tests/browser/deterministic.py \
  --dist /var/lib/nas-test/repo/cockpit/dist \
  --evidence /tmp/nas-deterministic-bundle.json
pass "Deterministic bundle XSS, layout, and console-error probes"

log "Custom command surfaces and generated configuration"
nas-secrets status | grep -q 'Runtime secrets: active'
run_as_admin_with_stdin "$(nas_vm_ordinary_wait_seconds)" nas-secrets show-ai-api-key | grep -Eq '^[0-9a-fA-F]{64}$'
! run_as_admin_with_stdin "$(nas_vm_ordinary_wait_seconds)" nas-secrets check-authentik-token \
  >/tmp/nas-token-warning.log 2>&1 || fail "bootstrap token reuse was not reported"
grep -q 'bootstrap token' /tmp/nas-token-warning.log
! run_as_admin_with_stdin "$(nas_vm_ordinary_wait_seconds)" nas-zfs-export-recovery-key /tmp/disabled-zfs-key \
  >/tmp/nas-zfs-export-disabled.log 2>&1 || fail "ZFS recovery key unexpectedly existed while encryption was disabled"
[[ ! -e /tmp/disabled-zfs-key ]] || fail "disabled ZFS recovery-key test left an output file"
nas-managed-services-control status | jq -e '.schemaVersion == 3 and (.services | length > 0)' >/dev/null
nas-managed-services-control document | jq -e '.document.services | type == "object"' >/dev/null
! nas-managed-services-control set '../ai-runtime' always >/tmp/nas-service-injection.log 2>&1 || fail "path-like service identifier was accepted"
! nas-managed-services-control set 'ai-runtime;touch /tmp/pwned' always >>/tmp/nas-service-injection.log 2>&1 || fail "shell-like service identifier was accepted"
[[ ! -e /tmp/pwned ]] || fail "service identifier injection created an unexpected file"
! run_as_admin nas-setup account apply --username '../operator' --disabled >/tmp/nas-account-injection.log 2>&1 || fail "path-like account username was accepted"
! run_as_admin nas-setup account apply --username 'operator;touch /tmp/nas-account-pwned' --disabled >>/tmp/nas-account-injection.log 2>&1 || fail "shell-like account username was accepted"
[[ ! -e /tmp/nas-account-pwned ]] || fail "account username injection created an unexpected file"
nas-cockpit-api overview | jq -e '.protectedReady == true and (.services | length > 0)' >/dev/null
nas-cockpit-api action health | jq -e '.ok == true' >/dev/null
nas-doctor --json | jq -e '.schemaVersion >= 1 and (.checks | type == "array")' >/tmp/nas-doctor.json
nas-state authorities | jq -e '.schemaVersion >= 1 and (.authorities | length > 0)' >/tmp/nas-state-authorities.json
rm -f /tmp/nas-qemu-state.tar.gz
nas-state export /tmp/nas-qemu-state.tar.gz --include-sensitive >/tmp/nas-state-export.json
[[ "$(stat -c '%a:%U:%G' /tmp/nas-qemu-state.tar.gz)" == "600:root:root" ]] || fail "state bundle permissions are unsafe"
nas-state validate /tmp/nas-qemu-state.tar.gz | jq -e '.schemaVersion >= 1' >/tmp/nas-state-validate.json
nas-state diff /tmp/nas-qemu-state.tar.gz --json | jq -e '.schemaVersion >= 1 and (.authorities | length > 0)' >/tmp/nas-state-diff.json
! nas-state restore /tmp/nas-qemu-state.tar.gz --confirm-host "$PUBLIC_HOST" >/tmp/nas-state-dry-restore.log 2>&1 || \
  fail "state restore mutated without --apply"
grep -q 'Restore requires --apply' /tmp/nas-state-dry-restore.log
rm -f /tmp/nas-qemu-state.tar.gz
NAS_PREFLIGHT_VERIFY_MANIFEST=0 nas-preflight
pass "all custom command surfaces and in-VM repository preflight succeeded"

log "Open WebUI and llama-swap start/stop/on-demand lifecycle"
nas-managed-services-control set ai-runtime always | jq -e '.ok == true' >/dev/null
wait_active nas-llama-swap.service
assert_http_responsive "llama-swap web interface" http://127.0.0.1:9292/ui/

nas-managed-services-control set ai-workspace always | jq -e '.ok == true' >/dev/null
wait_active open-webui.service
wait_http http://127.0.0.1:9380/health

nas-managed-services-control set ai-workspace off | jq -e '.ok == true' >/dev/null
wait_inactive open-webui.service
nas-managed-services-control set ai-runtime off | jq -e '.ok == true' >/dev/null
wait_inactive nas-llama-swap.service

printf '{"ai-runtime":"on-demand","ai-workspace":"on-demand"}' | nas-managed-services-control set-many - | jq -e '.ok == true' >/dev/null
nas-managed-services-control wake ai-workspace | jq -e '.ok == true' >/dev/null
wait_active nas-llama-swap.service
wait_active open-webui.service
wait_http http://127.0.0.1:9380/health
nas-managed-services-control set ai-workspace off >/dev/null
nas-managed-services-control set ai-runtime off >/dev/null
wait_inactive open-webui.service
wait_inactive nas-llama-swap.service
nas-managed-services-control set ai-downloader always | jq -e '.ok == true' >/dev/null
wait_active podman-hfdownloader.service
nas-managed-services-control set ai-downloader off | jq -e '.ok == true' >/dev/null
wait_inactive podman-hfdownloader.service
pass "Open WebUI, llama-swap, and ai-downloader start, stop, and wake correctly"

log "Observability, notifications, Syncthing, Vaultwarden, and Cockpit assets"
nas-managed-services-control set grafana always | jq -e '.ok == true' >/dev/null
for unit in \
  victoriametrics.service telegraf.service vmalert-nas.service \
  nas-alert-router.service grafana.service ntfy-sh.service \
  syncthing.service vaultwarden.service; do
  systemctl cat "$unit" >/dev/null 2>&1 || fail "expected enabled unit is missing: $unit"
  wait_active "$unit"
done
wait_http http://127.0.0.1:8428/victoriametrics/ping
wait_http http://127.0.0.1:3000/api/health
syncthing_key_file=/var/lib/syncthing/.config/syncthing/apikey
syncthing_config=/var/lib/syncthing/.config/syncthing/config.xml
if [[ -s "$syncthing_key_file" ]]; then
  syncthing_key="$(<"$syncthing_key_file")"
else
  syncthing_key="$(sed -nE 's#.*<apikey>([^<]+)</apikey>.*#\1#p' "$syncthing_config" | head -n1)"
fi
[[ -n "$syncthing_key" ]] || fail "Syncthing API key is missing from apikey and config.xml"
wait_http http://127.0.0.1:8384/rest/system/status -H "X-API-Key: $syncthing_key"
nas-identity-sync sync-syncthing | jq -e \
  'has("folders") and has("devices") and has("removedFolders") and has("removedDevices")' >/dev/null
wait_http http://127.0.0.1:8222/alive
assert_http_responsive "ntfy health endpoint" http://127.0.0.1:2586/v1/health
log "Notification dependency failure and recovery"
alert_payload='[{"labels":{"alertname":"QemuNtfyDependency","severity":"warning","instance":"qemu"},"annotations":{"summary":"ntfy outage test"}}]'
systemctl stop ntfy-sh.service
wait_inactive ntfy-sh.service
ntfy_down_code="$(curl --silent --output /tmp/nas-alert-ntfy-down.json --write-out '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary "$alert_payload" \
  http://127.0.0.1:9093/api/v2/alerts || true)"
[[ "$ntfy_down_code" == 502 ]] || fail "alert router did not surface ntfy outage as HTTP 502 (got $ntfy_down_code)"
! grep -q 'Traceback' /tmp/nas-alert-ntfy-down.json || fail "alert router leaked a traceback during ntfy outage"
systemctl start ntfy-sh.service
wait_active ntfy-sh.service
wait_http http://127.0.0.1:2586/v1/health
ntfy_recovered_code="$(curl --silent --output /tmp/nas-alert-ntfy-recovered.json --write-out '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary "$alert_payload" \
  http://127.0.0.1:9093/api/v2/alerts)"
[[ "$ntfy_recovered_code" == 200 ]] || fail "alert delivery did not recover after ntfy restart (HTTP $ntfy_recovered_code)"
pass "alert delivery fails explicitly during ntfy outage and recovers cleanly"
malformed_alert_code="$(curl --silent --output /tmp/nas-alert-malformed.json --write-out '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary '{' \
  http://127.0.0.1:9093/api/v2/alerts)"
[[ "$malformed_alert_code" == 400 ]] || fail "malformed alert JSON returned HTTP $malformed_alert_code"
python3 - <<'PYALERTBODY'
from pathlib import Path
Path('/tmp/nas-alert-oversized.json').write_bytes(b'[' + b' ' * (1024 * 1024 + 4096) + b']')
PYALERTBODY
oversized_alert_code="$(curl --silent --output /tmp/nas-alert-oversized-response.json --write-out '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary @/tmp/nas-alert-oversized.json \
  http://127.0.0.1:9093/api/v2/alerts)"
[[ "$oversized_alert_code" == 413 ]] || fail "oversized alert body returned HTTP $oversized_alert_code"
rm -f /tmp/nas-alert-oversized.json
pass "installed alert router rejects malformed and oversized notifier input"
! nas-alert $'Injected title\r\nX-NAS-Test: injected' 'must not send' >/tmp/nas-alert-header-injection.log 2>&1 || \
  fail "nas-alert accepted a CRLF header-injection title"
grep -q 'one line' /tmp/nas-alert-header-injection.log
nas-alert 'QEMU integration test' 'NixOS NAS notification path is healthy.'
find /run/current-system/sw/share/cockpit /nix/store -maxdepth 6 -path '*cockpit*zfs*' -print -quit 2>/dev/null | grep -q .
find /run/current-system/sw/share/cockpit /nix/store -maxdepth 8 -path '*nas*docs*index.html' -print -quit 2>/dev/null | grep -q .
pass "supporting services and Cockpit plugin assets are present"

log "Secret stop/reactivation transaction"
run_as_admin nas-secrets stop
wait_inactive caddy.service
wait_inactive copyparty.service
wait_inactive authentik.service
wait_inactive nas-zfs-mount-guard.service
wait_active nas-cockpit-sso.service
! systemctl is-active --quiet cockpit.socket || fail "stock Cockpit socket started after setup"
ss -tln | grep -Eq '127\.0\.0\.1:9092[[:space:]]' || fail "Cockpit SSO session is not loopback-only"
[[ ! -e /run/nas-secrets ]] || fail "runtime secret tree survived nas-secrets stop"

activate_secrets
wait_active caddy.service
wait_active copyparty.service
wait_active authentik.service

! printf '%s\n' wrong-password | run_as_admin nas-secrets activate-stdin \
  >/tmp/nas-secrets-wrong-active.log 2>&1 || fail "wrong password was accepted while active"
systemctl is-active --quiet nas-protected-services.target
[[ -f /run/nas-secrets/ready ]]
pass "secret stop, reactivation, and wrong-password rollback behavior passed"

log "Final state"
zpool status -x tank | grep -Eq 'pool .tank. is healthy|all pools are healthy'
systemctl --failed --no-legend --plain | grep -Ev '(^$|nas-health-alert@)' >/tmp/nas-failed-final || true
[[ ! -s /tmp/nas-failed-final ]] || { cat /tmp/nas-failed-final >&2; fail "unexpected failed units remain"; }
printf '\nALL NIXOS NAS VM TESTS PASSED\n'
