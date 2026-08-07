#!/usr/bin/env bash
set -Eeuo pipefail

ZFS_DEVICE="${1:-${NAS_TEST_ZFS_DEVICE:-/dev/vdb}}"
KEEPASS_PASSWORD="${NAS_TEST_KEEPASS_PASSWORD:-nixos-nas-vm-test-password}"
PUBLIC_HOST="${NAS_TEST_PUBLIC_HOST:-nas-test.local}"
CONFIG_DIR="${NAS_CONFIG_DIR:-/var/lib/nas-test/repo}"
TEST_TIMEOUT="${NAS_TEST_TIMEOUT:-300}"

log() { printf '\n==> %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

on_error() {
  local rc=$?
  printf '\nVM validation failed with status %s.\n' "$rc" >&2
  systemctl --failed --no-pager >&2 || true
  journalctl -b -n 250 --no-pager >&2 || true
  zpool status >&2 || true
  exit "$rc"
}
trap on_error ERR

require_commands() {
  local missing=() command
  for command in "$@"; do
    command -v "$command" >/dev/null 2>&1 || missing+=("$command")
  done
  ((${#missing[@]} == 0)) || fail "missing commands: ${missing[*]}"
}

wait_active() {
  local unit=$1
  timeout "$TEST_TIMEOUT" bash -c "until systemctl is-active --quiet '$unit'; do sleep 2; done"
}

wait_inactive() {
  local unit=$1
  timeout "$TEST_TIMEOUT" bash -c "until ! systemctl is-active --quiet '$unit'; do sleep 2; done"
}

wait_http() {
  local url=$1
  shift
  timeout "$TEST_TIMEOUT" bash -c \
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

assert_blocked() {
  local path=$1 code
  code="$(http_code --resolve "$PUBLIC_HOST:443:127.0.0.1" "https://$PUBLIC_HOST$path")"
  case "$code" in
    301|302|303|307|308|401|403) pass "unauthenticated $path is blocked or redirected ($code)" ;;
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
    301|302|303|307|308|401|403) pass "spoofed identity headers do not bypass $path ($code)" ;;
    *) fail "spoofed identity headers bypassed or unexpectedly reached $path (HTTP $code)" ;;
  esac
}

run_as_admin() {
  runuser -u admin -- env HOME=/home/admin PATH="$PATH" bash -lc "$1"
}

activate_secrets() {
  run_as_admin "printf '%s\\n' '$KEEPASS_PASSWORD' | timeout 600 nas-secrets activate-stdin"
}

require_commands \
  curl findmnt firewall-cmd git ip jq keepassxc-cli nas-alert nas-cockpit-api nas-feature-control \
  nas-identity-sync nas-operation-run nas-preflight nas-secrets nas-setup nas-update nas-ups-init-password \
  nas-zfs-create-encrypted-dataset nas-zfs-export-recovery-key nas-zfs-lock \
  nas-zfs-mount-check nas-zfs-unlock python3 ss systemctl zfs zpool

log "Locked-state and configuration checks"
wait_active cockpit.socket
wait_active nas-first-start.service
systemctl show nas-first-start.service --property=RemainAfterExit --value | grep -qx yes
jq -e '.schemaVersion == 1 and (.status | type == "string")' /var/lib/nas-first-start/status.json >/dev/null
systemctl restart nas-first-start.service
wait_active nas-first-start.service
jq -e '.schemaVersion == 1 and (.status | type == "string")' /var/lib/nas-first-start/status.json >/dev/null
pass "first-start oneshot remains active and republishes readiness across restart"
[[ ! -e /run/nas-secrets/ready ]] || fail "runtime secrets were unexpectedly active at boot"
! systemctl is-active --quiet caddy.service || fail "Caddy must remain stopped while locked"
! systemctl is-active --quiet copyparty.service || fail "CopyParty must remain stopped while locked"
! systemctl is-active --quiet authentik.service || fail "Authentik must remain stopped while locked"
code="$(http_code https://127.0.0.1:9092/console/ || true)"
case "$code" in
  200|301|302|303|307|308|401) pass "locked-state Cockpit endpoint is reachable ($code)" ;;
  *) fail "locked-state Cockpit endpoint returned HTTP ${code:-none}" ;;
esac

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
install -d -m 0700 -o admin -g users /var/lib/nas-test/setup
printf '%s\n' 'alice-vm-password' >/var/lib/nas-test/setup/alice.password
printf '%s\n' 'operator-vm-password' >/var/lib/nas-test/setup/operator.password
printf '%s\n' 'baseline-vm-password' >/var/lib/nas-test/setup/baseline.password
chown admin:users /var/lib/nas-test/setup/*.password
chmod 0600 /var/lib/nas-test/setup/*.password
cat >/var/lib/nas-test/setup/first-run.json <<EOFSETUP
{
  "schemaVersion": 1,
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
      "groups": ["nas_admin", "nas_allow_files", "nas_allow_ai", "nas_allow_vault", "nas_allow_syncthing"],
      "passwordFile": "/var/lib/nas-test/setup/operator.password"
    },
    {
      "username": "alice",
      "name": "Alice Example",
      "email": "alice@nas.local",
      "groups": ["nas_users", "nas_allow_files", "nas_allow_vault", "nas_allow_syncthing"],
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
  "features": {},
  "runPreflight": true
}
EOFSETUP
chown admin:users /var/lib/nas-test/setup/first-run.json
chmod 0600 /var/lib/nas-test/setup/first-run.json
run_as_admin "nas-setup validate-config /var/lib/nas-test/setup/first-run.json | jq -e '.accounts | length == 4'"
plan_json="$(run_as_admin "nas-setup prepare-first-start --config /var/lib/nas-test/setup/first-run.json")"
plan_digest="$(jq -er '.planDigest | select(test("^[0-9a-f]{64}$"))' <<<"$plan_json")"
stale_digest="$(printf '0%.0s' {1..64})"
if run_as_admin "nas-setup first-run --config /var/lib/nas-test/setup/first-run.json --confirm-plan-digest '$stale_digest'" >/tmp/nas-stale-plan.out 2>/tmp/nas-stale-plan.err; then
  fail "first-run accepted a stale plan digest"
fi
grep -qi 'plan.*changed\|digest' /tmp/nas-stale-plan.err || fail "stale plan digest failure was not diagnostic"
pass "first-run rejects a stale plan digest before mutation"
run_as_admin "printf '%s\n' '$KEEPASS_PASSWORD' | timeout 1200 nas-setup first-run \
  --config /var/lib/nas-test/setup/first-run.json \
  --keepass-password-stdin \
  --confirm-plan-digest '$plan_digest' \
  --confirm-storage-device '$ZFS_DEVICE' \
  --allow-destructive-storage" >/tmp/nas-first-run.json
jq -e '
  .storage.createdPool == true and
  .storage.createdDataset == true and
  (.accounts.created | sort) == ["alice", "baseline", "guest", "operator"] and
  (.identity.administrators | index("operator")) != null
' /tmp/nas-first-run.json >/dev/null
nas-setup status | jq -e '
  .runtimeSecretsActive == true and
  .poolPresent == true and
  .datasetPresent == true and
  .setupState
' >/dev/null
[[ -d /tank/shares/users/alice && -d /tank/shares/users/operator ]]
[[ "$(stat -c '%a:%U:%G' /tank/shares/users/alice)" == "2770:copyparty:copyparty" ]]
findmnt -n -o FSTYPE,SOURCE,TARGET /tank | grep -q '^zfs tank/nas /tank$'
pass "nas-setup created storage, KeePass secrets, accounts, shares, and activated the stack"

log "Adversarial command, SQL-like input, and HTTP validation"
rm -f /tmp/nas-command-injection-marker
if nas-cockpit-api feature 'aiWorkspace;touch${IFS}/tmp/nas-command-injection-marker' always >/tmp/nas-bad-feature.out 2>/tmp/nas-bad-feature.err; then
  fail "Cockpit API accepted a command-injection-shaped feature identifier"
fi
[[ ! -e /tmp/nas-command-injection-marker ]] || fail "feature identifier escaped into shell execution"
if nas-setup account disable "' OR '1'='1" >/tmp/nas-bad-account.out 2>/tmp/nas-bad-account.err; then
  fail "account command accepted an SQL-injection-shaped username"
fi
cat >/tmp/nas-bad-path-config.json <<'EOF_BAD_CONFIG'
{"schemaVersion":1,"storage":{"createPool":true,"devices":["../../dev/vdb"]}}
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
  authentik.service nas-identity-sync.service copyparty.service \
  nas-on-demand-gate.service caddy.service; do
  wait_active "$unit"
done
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
  .capabilities.files.allowed == true and .capabilities.ai.allowed == false
' >/dev/null
run_as_admin "printf '%s\n' 'alice-updated-password' | nas-setup account apply \
  --username alice \
  --password-stdin" >/tmp/nas-account-password-update.json
jq -e '.account.updated == ["alice"]' /tmp/nas-account-password-update.json >/dev/null
run_as_admin "nas-setup account apply --username alice --name '<img src=x onerror=document.body.dataset.nasXss=1>'" \
  >/tmp/nas-account-xss-name.json
jq -e '.account.updated == ["alice"]' /tmp/nas-account-xss-name.json >/dev/null
nas-identity-sync export-account alice | jq -e '
  .active == true and
  (.groups | index("nas_allow_files")) != null and
  (.groups | index("nas_allow_vault")) != null and
  (.groups | index("nas_allow_syncthing")) != null
' >/dev/null
run_as_admin "printf '%s\n' 'temporary-password' | nas-setup account apply \
  --username temporary \
  --name 'Temporary User' \
  --email temporary@nas.local \
  --group nas_allow_files \
  --password-stdin" >/tmp/nas-account-add.json
jq -e '.account.created == ["temporary"]' /tmp/nas-account-add.json >/dev/null
run_as_admin "nas-setup account disable temporary" >/tmp/nas-account-disable.json
jq -e '.updated == ["temporary"]' /tmp/nas-account-disable.json >/dev/null
nas-identity-sync export-account temporary | jq -e '
  .active == false and
  (.groups | index("nas_disabled")) != null and
  (.groups | index("nas_admin")) == null and
  (.groups | index("nas_allow_files")) == null
' >/dev/null
pass "core services, account apply/disable CLI, and CopyParty backend are healthy"

log "Anonymous read-only TFTP behavior"
[[ -d /tank/shares/tftp ]] || fail "ZFS-backed TFTP directory was not created"
printf 'nixos-nas-qemu-tftp\n' >/tank/shares/tftp/qemu-tftp.txt
chown copyparty:copyparty /tank/shares/tftp/qemu-tftp.txt
chmod 0660 /tank/shares/tftp/qemu-tftp.txt
timeout "$TEST_TIMEOUT" bash -c \
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
sock.sendto(packet(2, upload), SERVER)
response, _peer = sock.recvfrom(65535)
opcode = struct.unpack("!H", response[:2])[0]
if opcode != 5:
    raise SystemExit(f"read-only TFTP accepted a write request (opcode={opcode})")
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
  'http://localhost/authorize?feature=aiRuntime&scope=admin')"
case "$gate_admin" in 200|204) : ;; *) fail "administrator-only feature gate returned HTTP $gate_admin" ;; esac
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
if len(parts) < 2 or parts[1] not in {"400", "401", "403"}:
    raise SystemExit(f"control-character group header was not rejected fail-closed: {first!r}")
PYHOSTILEGATE
pass "malformed trusted identity headers remain fail-closed inside the installed gate"
nas-feature-control set aiRuntime off >/dev/null
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
wait_http http://127.0.0.1:9000/-/health/live/
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
ip link del nas-untrusted-host >/dev/null 2>&1 || true
ip netns add nas-untrusted-test
ip link add nas-untrusted-host type veth peer name nas-untrusted-client
ip link set nas-untrusted-client netns nas-untrusted-test
ip addr add 198.18.0.1/30 dev nas-untrusted-host
ip link set nas-untrusted-host up
ip netns exec nas-untrusted-test ip link set lo up
ip netns exec nas-untrusted-test ip addr add 198.18.0.2/30 dev nas-untrusted-client
ip netns exec nas-untrusted-test ip link set nas-untrusted-client up
for port in 22 80 443 9092 22000; do
  if ip netns exec nas-untrusted-test python3 -c \
    'import socket,sys; s=socket.socket(); s.settimeout(1.0); raise SystemExit(0 if s.connect_ex(("198.18.0.1", int(sys.argv[1]))) == 0 else 1)' \
    "$port"; then
    fail "untrusted namespace reached protected TCP port $port"
  fi
done
ip netns del nas-untrusted-test
ip link del nas-untrusted-host >/dev/null 2>&1 || true
pass "untrusted interface cannot reach SSH, HTTP(S), Cockpit, or Syncthing while trusted-zone services remain available"

log "Browser-level Authentik and capability authorization"
authz_secret_dir=$(mktemp -d /run/nas-authz-test.XXXXXX)
cleanup_authz_secrets() { rm -rf -- "$authz_secret_dir"; }
trap cleanup_authz_secrets EXIT
chmod 0700 "$authz_secret_dir"
printf '%s\n' operator-vm-password > "$authz_secret_dir/operator"
printf '%s\n' alice-updated-password > "$authz_secret_dir/alice"
printf '%s\n' baseline-vm-password > "$authz_secret_dir/baseline"
chmod 0600 "$authz_secret_dir"/*
timeout 300 python3 /var/lib/nas-test/repo/tests/browser/authz.py \
  --origin "https://$PUBLIC_HOST" \
  --operator-password-file "$authz_secret_dir/operator" \
  --alice-password-file "$authz_secret_dir/alice" \
  --baseline-password-file "$authz_secret_dir/baseline"
cleanup_authz_secrets
trap - EXIT
pass "Browser authorization and Authentik user-settings flow"

log "Custom command surfaces and generated configuration"
nas-secrets status | grep -q 'Runtime secrets: active'
run_as_admin "printf '%s\\n' '$KEEPASS_PASSWORD' | nas-secrets show-ai-api-key" | grep -Eq '^[0-9a-fA-F]{64}$'
! run_as_admin "printf '%s\\n' '$KEEPASS_PASSWORD' | nas-secrets check-authentik-token" \
  >/tmp/nas-token-warning.log 2>&1 || fail "bootstrap token reuse was not reported"
grep -q 'bootstrap token' /tmp/nas-token-warning.log
! run_as_admin "printf '%s\\n' '$KEEPASS_PASSWORD' | nas-zfs-export-recovery-key /tmp/disabled-zfs-key" \
  >/tmp/nas-zfs-export-disabled.log 2>&1 || fail "ZFS recovery key unexpectedly existed while encryption was disabled"
[[ ! -e /tmp/disabled-zfs-key ]] || fail "disabled ZFS recovery-key test left an output file"
nas-feature-control status | jq -e '.schemaVersion == 2 and (.features | length > 0)' >/dev/null
! nas-feature-control set '../aiRuntime' always >/tmp/nas-feature-injection.log 2>&1 || fail "path-like feature identifier was accepted"
! nas-feature-control set 'aiRuntime;touch /tmp/pwned' always >>/tmp/nas-feature-injection.log 2>&1 || fail "shell-like feature identifier was accepted"
[[ ! -e /tmp/pwned ]] || fail "feature identifier injection created an unexpected file"
! run_as_admin "nas-setup account apply --username '../operator' --disabled" >/tmp/nas-account-injection.log 2>&1 || fail "path-like account username was accepted"
! run_as_admin "nas-setup account apply --username 'operator;touch /tmp/nas-account-pwned' --disabled" >>/tmp/nas-account-injection.log 2>&1 || fail "shell-like account username was accepted"
[[ ! -e /tmp/nas-account-pwned ]] || fail "account username injection created an unexpected file"
nas-cockpit-api overview | jq -e '.protectedReady == true and (.services | length > 0)' >/dev/null
nas-cockpit-api action health | jq -e '.ok == true' >/dev/null
nas-doctor --json | jq -e '.schemaVersion >= 1 and (.checks | type == "array")' >/tmp/nas-doctor.json
nas-migrate-state plan | jq -e '.schemaVersion == 1 and .status != "manual-recovery-required"' >/tmp/nas-migration-plan.json
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
python3 /var/lib/nas-test/repo/tests/vm/adversarial-installed.py >/tmp/nas-installed-command-fuzz.json
expected_installed_commands="$(jq '[.executables[] | select(.fuzzStrategy != null)] | length' /var/lib/nas-test/repo/tests/custom-script-contracts.json)"
jq -e --argjson expected "$expected_installed_commands" '.ok == true and .commands == $expected' /tmp/nas-installed-command-fuzz.json >/dev/null
pass "all custom command surfaces, installed adversarial command fuzzing, and in-VM repository preflight succeeded"

log "Open WebUI and llama-swap start/stop/on-demand lifecycle"
nas-feature-control set aiRuntime always | jq -e '.ok == true' >/dev/null
wait_active nas-llama-swap.service
assert_http_responsive "llama-swap web interface" http://127.0.0.1:9292/ui/

nas-feature-control set aiWorkspace always | jq -e '.ok == true' >/dev/null
wait_active open-webui.service
wait_http http://127.0.0.1:9380/health

nas-feature-control set aiWorkspace off | jq -e '.ok == true' >/dev/null
wait_inactive open-webui.service
nas-feature-control set aiRuntime off | jq -e '.ok == true' >/dev/null
wait_inactive nas-llama-swap.service

nas-feature-control set aiRuntime on-demand | jq -e '.ok == true' >/dev/null
nas-feature-control set aiWorkspace on-demand | jq -e '.ok == true' >/dev/null
nas-feature-control wake aiWorkspace | jq -e '.ok == true' >/dev/null
wait_active nas-llama-swap.service
wait_active open-webui.service
wait_http http://127.0.0.1:9380/health
nas-feature-control set aiWorkspace off >/dev/null
nas-feature-control set aiRuntime off >/dev/null
wait_inactive open-webui.service
wait_inactive nas-llama-swap.service
pass "Open WebUI and llama-swap start, stop, and wake correctly"

log "Observability, notifications, Syncthing, Vaultwarden, and Cockpit assets"
nas-feature-control set grafana always | jq -e '.ok == true' >/dev/null
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
run_as_admin "nas-secrets stop"
wait_inactive caddy.service
wait_inactive copyparty.service
wait_inactive authentik.service
wait_inactive nas-zfs-mount-guard.service
wait_active cockpit.socket
[[ ! -e /run/nas-secrets ]] || fail "runtime secret tree survived nas-secrets stop"

activate_secrets
wait_active caddy.service
wait_active copyparty.service
wait_active authentik.service

! run_as_admin "printf '%s\\n' wrong-password | nas-secrets activate-stdin" \
  >/tmp/nas-secrets-wrong-active.log 2>&1 || fail "wrong password was accepted while active"
systemctl is-active --quiet nas-protected-services.target
[[ -f /run/nas-secrets/ready ]]
pass "secret stop, reactivation, and wrong-password rollback behavior passed"

log "Final state"
zpool status -x tank | grep -Eq 'pool .tank. is healthy|all pools are healthy'
systemctl --failed --no-legend --plain | grep -Ev '(^$|nas-health-alert@)' >/tmp/nas-failed-final || true
[[ ! -s /tmp/nas-failed-final ]] || { cat /tmp/nas-failed-final >&2; fail "unexpected failed units remain"; }
printf '\nALL NIXOS NAS VM TESTS PASSED\n'
