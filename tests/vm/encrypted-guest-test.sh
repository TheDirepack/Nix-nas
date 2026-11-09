#!/usr/bin/env bash
set -Eeuo pipefail

ZFS_DEVICE="${1:-${NAS_TEST_ZFS_DEVICE:-/dev/vdb}}"
KEEPASS_PASSWORD="${NAS_TEST_KEEPASS_PASSWORD:-nixos-nas-vm-test-password}"
TEST_TIMEOUT="${NAS_TEST_TIMEOUT:-$(nas_vm_ordinary_wait_seconds)}"
SETUP_ENTRYPOINT="${2:-cli}"

log() { printf '\n==> %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ "$SETUP_ENTRYPOINT" == cli || "$SETUP_ENTRYPOINT" == api ]] || fail "unknown encrypted setup entrypoint"

on_error() {
  local rc=$?
  # Only script coordinates are logged: BASH_COMMAND and arguments can contain secrets.
  local source_file="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
  local source_line="${BASH_LINENO[0]:-0}"
  local source_function="${FUNCNAME[1]:-main}"
  printf '\nEncrypted VM validation failed with status %s at %s:%s (%s).\n' \
    "$rc" "$source_file" "$source_line" "$source_function" >&2
  systemctl --failed --no-pager >&2 || true
  journalctl -b -n 250 --no-pager >&2 || true
  zpool status >&2 || true
  exit "$rc"
}
trap on_error ERR

wait_active() {
  local unit=$1
  timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "$TEST_TIMEOUT" bash -c "until systemctl is-active --quiet '$unit'; do sleep 2; done"
}

wait_inactive() {
  local unit=$1
  timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "$TEST_TIMEOUT" bash -c "until ! systemctl is-active --quiet '$unit'; do sleep 2; done"
}

wait_oneshot_completed() {
  local unit=$1 started state result deadline=$((SECONDS + TEST_TIMEOUT))
  while ((SECONDS < deadline)); do
    started="$(systemctl show "$unit" --property=ExecMainStartTimestampMonotonic --value)"
    state="$(systemctl show "$unit" --property=ActiveState --value)"
    result="$(systemctl show "$unit" --property=Result --value)"
    if [[ "$started" != 0 && "$state" != activating && "$result" == success ]]; then
      return 0
    fi
    if [[ "$state" == failed || ( "$started" != 0 && "$state" != activating && "$result" != success ) ]]; then
      systemctl status "$unit" --no-pager >&2 || true
      fail "$unit did not complete successfully"
    fi
    sleep 2
  done
  systemctl status "$unit" --no-pager >&2 || true
  fail "timed out waiting for $unit to complete"
}

wait_reconciliation_idle() {
  systemctl start nas-managed-services-reconcile.service
  wait_oneshot_completed nas-managed-services-reconcile.service
  wait_inactive nas-managed-services-reconcile.service
  [[ ! -e /run/nas-control/reconcile.pending ]] || fail "managed-services reconciliation remains pending"
}

prime_nasadmin_sudo() {
  local password
  runuser -u nasadmin -- sudo -n -v >/dev/null 2>&1 && return 0
  password="$(cat /var/lib/nas-test/setup/nasadmin.password)"
  NASADMIN_PASSWORD="$password" expect <<'EXPECT_SUDO' || fail "nasadmin sudo priming failed"
set timeout 30
spawn runuser -u nasadmin -- sudo -v
expect {
  -re "(?i)password.*:" { send "$env(NASADMIN_PASSWORD)\r"; exp_continue }
  eof { }
  timeout { exit 99 }
}
set status [lindex [wait] 3]
exit $status
EXPECT_SUDO
}

run_as_admin() {
  # Keep cwd off /tank so the encryption-root lock can unmount the dataset.
  if [[ -r /var/lib/nas-setup/local-administrator.json ]]; then
    prime_nasadmin_sudo
    runuser -u nasadmin -- env -C / HOME=/tank/homes/nasadmin PATH="$PATH" "$@"
  else
    runuser -u admin -- env -C / HOME=/home/admin PATH="$PATH" "$@"
  fi
}

activate_secrets() {
  run_as_admin_with_stdin "$(nas_vm_timeout_value secretActivation)" nas-secrets activate-stdin
}

run_as_admin_with_stdin() {
  local timeout_seconds=$1
  shift
  if [[ -r /var/lib/nas-setup/local-administrator.json ]]; then
    prime_nasadmin_sudo
    nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" \
      runuser -u nasadmin -- env -C / HOME=/tank/homes/nasadmin PATH="$PATH" \
        timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" "$timeout_seconds" "$@"
  else
    nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" \
      runuser -u admin -- env -C / HOME=/home/admin PATH="$PATH" \
        timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" "$timeout_seconds" "$@"
  fi
}

log "Verify encrypted fixture starts locked"
! systemctl is-active --quiet cockpit.socket || fail "stock Cockpit socket must stay inactive while locked"
wait_active nas-cockpit-sso.service
[[ -S /run/nas-cockpit-sso/ws.sock ]] || fail "Cockpit permissioned Unix listener is missing"
! ss -ltnp | grep -F 'cockpit-ws' || fail "Unauthenticated Cockpit root bridge opened a TCP listener"
! ss -tln | grep -Eq ':9092[[:space:]]' || fail "Unauthenticated root Cockpit TCP listener is exposed"
[[ ! -e /run/nas-secrets/ready ]] || fail "runtime secrets were unexpectedly active"
! systemctl is-active --quiet nas-protected-services.target || fail "protected services started before unlock"
[[ ! -e /run/nas-control/effective.json ]] || fail "managed state was compiled before unlock"
systemctl start nas-managed-services-authentik-reconcile.service
[[ "$(systemctl show nas-managed-services-authentik-reconcile.service --property=ConditionResult --value)" == no ]] || \
  fail "managed Authentik projection was not condition-skipped while locked"
[[ "$(systemctl show nas-managed-services-authentik-reconcile.service --property=ExecMainStartTimestampMonotonic --value)" == 0 ]] || \
  fail "managed Authentik projection executed before unlock"
[[ "$(systemctl show nas-managed-services-authentik-reconcile.service --property=ActiveState --value)" == inactive ]] || \
  fail "managed Authentik projection is not inactive while locked"

for _ in $(seq 1 60); do
  [[ -b "$ZFS_DEVICE" ]] && break
  sleep 1
done
[[ -b "$ZFS_DEVICE" ]] || fail "ZFS test disk did not appear: $ZFS_DEVICE"

log "Run first-time setup through the encrypted-ZFS path"
install -d -m 0700 -o admin -g users /var/lib/nas-test/setup
printf '%s\n' 'nasadmin-vm-password' >/var/lib/nas-test/setup/nasadmin.password
chmod 0600 /var/lib/nas-test/setup/nasadmin.password
plan_path=/var/lib/nas-test/setup/encrypted-first-run.json
[[ ! -e "$plan_path" ]] || fail "encrypted setup unexpectedly has a prepared plan"
jq -cn --arg device "$ZFS_DEVICE" \
  '{storage:{createPool:true,devices:[$device],wipeDevices:true}}' | \
  nas-setup create-first-start-plan --config "$plan_path" >/tmp/nas-encrypted-plan.json
plan_digest="$(jq -er '.planDigest' /tmp/nas-encrypted-plan.json)"
make_setup_payload() {
  python3 -c 'import json,sys,pathlib; json.dump({"keepass":sys.stdin.readline().rstrip("\n"), "administrator":{"username":"nasadmin", "name":"NAS Administrator", "email":"nasadmin@nas-test.local", "password":pathlib.Path(sys.argv[1]).read_text().rstrip("\n")}},sys.stdout)' \
    /var/lib/nas-test/setup/nasadmin.password
}
make_setup_api_payload() {
  python3 -c 'import json,sys; value=json.load(sys.stdin); value["password"]=value.pop("keepass"); value.update(planDigest=sys.argv[2], devices=[sys.argv[1]], allowDestructiveStorage=True, encryptStorage=True, confirmPasswordReapply=False); json.dump(value,sys.stdout)' \
    "$ZFS_DEVICE" "$1"
}
wait_active nas-setup-api.service
setup_sock=/run/nas-setup-api/setup.sock
setup_api=http://localhost/setup/api
curl --fail --silent --show-error --max-time 60 --unix-socket "$setup_sock" \
  "$setup_api/first-start" >/tmp/nas-encrypted-api-plan.json
jq -e --arg digest "$plan_digest" '.status == "ready" and .planDigest == $digest' \
  /tmp/nas-encrypted-api-plan.json >/dev/null || fail "setup API did not expose the CLI-created plan"
stale_code="$(nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" make_setup_payload | \
  make_setup_api_payload "$(printf '0%.0s' {1..64})" | \
  curl --silent --show-error --max-time 60 -o /tmp/nas-api-stale-plan.json -w '%{http_code}' \
    -H 'Content-Type: application/json' --data-binary @- --unix-socket "$setup_sock" "$setup_api/first-run")"
[[ "$stale_code" == 400 ]] || fail "setup API accepted a stale plan digest (HTTP $stale_code)"
jq -e '.error | contains("plan is stale")' /tmp/nas-api-stale-plan.json >/dev/null || \
  fail "setup API stale plan rejection was not diagnostic"
[[ ! -e /var/lib/nas-control-plane/nas-secrets/NAS.kdbx ]] || fail "rejected API setup created secrets"
! zpool list -H tank >/dev/null 2>&1 || fail "rejected API setup created storage"
pass "setup API rejects a stale plan digest before mutation"
if nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" make_setup_payload | \
  env NAS_SETUP_ALLOW_ROOT=1 nas-setup first-run --config "$plan_path" \
    --secret-payload-stdin --encrypt-storage --confirm-plan-digest "$(printf '0%.0s' {1..64})" \
    --confirm-storage-device "$ZFS_DEVICE" --allow-destructive-storage \
    >/tmp/nas-cli-stale-plan.json 2>/tmp/nas-cli-stale-plan.err; then
  fail "CLI setup accepted a stale plan digest"
fi
grep -qi 'no longer matches' /tmp/nas-cli-stale-plan.err
[[ ! -e /var/lib/nas-control-plane/nas-secrets/NAS.kdbx ]] || fail "rejected CLI setup created secrets"
! zpool list -H tank >/dev/null 2>&1 || fail "rejected CLI setup created storage"
if [[ "$SETUP_ENTRYPOINT" == api ]]; then
  job_submission="$(nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" make_setup_payload | \
    make_setup_api_payload "$plan_digest" | \
    curl --fail --silent --show-error --max-time 60 -H 'Content-Type: application/json' \
      --data-binary @- --unix-socket "$setup_sock" "$setup_api/first-run")"
  job_capability="$(jq -er '.capability | select(test("^[0-9a-f]{48}$"))' <<<"$job_submission")"
  job_deadline=$((SECONDS + $(nas_vm_timeout_value firstRun)))
  job_status=pending
  while ((SECONDS < job_deadline)); do
    if job_result="$(printf 'header = "X-NAS-Setup-Capability: %s"\n' "$job_capability" | \
      curl --config - --fail --silent --max-time 30 --unix-socket "$setup_sock" "$setup_api/first-start/job")"; then
      job_status="$(jq -er .status <<<"$job_result")"
      [[ "$job_status" == complete || "$job_status" == complete-unverified || "$job_status" == failed ]] && break
    fi
    sleep 2
  done
  [[ "$job_status" == complete ]] || fail "encrypted API setup did not complete (status $job_status)"
  jq -e '.result | type == "object"' <<<"$job_result" >/dev/null
  jq '.result' <<<"$job_result" >/tmp/nas-encrypted-setup.json
  unset job_submission job_capability
  pass "fresh encrypted setup API job completed"
else
  nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" make_setup_payload | \
    env NAS_SETUP_ALLOW_ROOT=1 timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
      "$(nas_vm_timeout_value firstRun)" nas-setup first-run --config "$plan_path" \
      --secret-payload-stdin --encrypt-storage --confirm-plan-digest "$plan_digest" \
      --confirm-storage-device "$ZFS_DEVICE" --allow-destructive-storage >/tmp/nas-encrypted-setup.json
fi
jq -e '.status == "complete" and .storage.createdPool == true and .storage.encrypted == true and .preflight == true and .localAdministrator.username == "nasadmin"' \
  /tmp/nas-encrypted-setup.json >/dev/null || fail "encrypted CLI setup did not complete with verification"
wait_oneshot_completed nas-managed-services-authentik-reconcile.service
[[ "$(systemctl show nas-managed-services-authentik-reconcile.service --property=ConditionResult --value)" == yes ]] || \
  fail "managed Authentik projection was skipped after secret activation"
[[ -s /var/lib/nas-control/authentik-v2-objects.json ]] || fail "managed Authentik projection did not commit its object manifest"
pass "managed Authentik projection executes after secret activation"
nas-managed-services-control status | jq -e '.schemaVersion == 3 and (.services | length > 0)' >/dev/null
nas-managed-services-control document | jq -e '.document.services | type == "object"' >/dev/null
pass "nas-managed-services-control reports the seeded V2 authority"
[[ "$(getent passwd akadmin)" == "" ]] || fail "bootstrap administrator was not retired after first run"
pass "$SETUP_ENTRYPOINT first start created and activated the encrypted storage stack"
wait_active nas-protected-services.target
wait_active nas-zfs-unlock.service
wait_active nas-zfs-mount-guard.service
nas-zfs-mount-check
[[ "$(zfs get -H -o value encryptionroot tank/nas)" == "tank/nas" ]]
[[ "$(zfs get -H -o value keyformat tank/nas)" == "hex" ]]
[[ "$(zfs get -H -o value keylocation tank/nas)" == "file:///run/nas-secret-runtime/live/zfs/dataset-key" ]]
[[ "$(zfs get -H -o value keystatus tank/nas)" == "available" ]]
[[ "$(zfs get -H -o value mounted tank/nas)" == "yes" ]]
[[ -f /run/nas-secrets/zfs/dataset-key ]]
[[ "$(stat -c '%a:%U:%G' /run/nas-secrets/zfs/dataset-key)" == "400:root:root" ]]
nas-setup status | jq -e '
  .runtimeSecretsActive == true and
  .poolPresent == true and
  .datasetPresent == true and
  .setupState.storage.encrypted == true
' >/dev/null
pass "nas-setup created and activated the encrypted storage stack"

! run_as_admin nas-zfs-create-encrypted-dataset >/tmp/nas-zfs-create-existing.log 2>&1 || \
  fail "direct encrypted-dataset command recreated an existing encryption root"
grep -q 'already exists' /tmp/nas-zfs-create-existing.log
pass "direct encrypted-dataset command refuses to modify an existing encryption root"

log "Fault-inject every encrypted dataset bootstrap transition"
# Keep the known-good encryption root out of the command's configured name while the
# failure matrix repeatedly creates and tears down a brand-new tank/nas. Locking first
# means the preserved dataset is unmounted and no protected consumer can write to it.
wait_reconciliation_idle
run_as_admin nas-zfs-lock
wait_inactive nas-protected-services.target
zfs rename tank/nas tank/nas-preserved
[[ "$(zfs get -H -o value mounted tank/nas-preserved)" == "no" ]]
for step in create keylocation fingerprint canmount unmount unload-key; do
  rm -f "/tmp/nas-zfs-fault-$step.out" "/tmp/nas-zfs-fault-$step.err"
  if nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" run_as_admin \
    env NAS_TEST_FAULT_INJECTION=1 NAS_TEST_ZFS_BOOTSTRAP_FAIL_AFTER="$step" \
    nas-zfs-create-encrypted-dataset \
    >"/tmp/nas-zfs-fault-$step.out" 2>"/tmp/nas-zfs-fault-$step.err"; then
    fail "ZFS bootstrap fault injection unexpectedly succeeded after $step"
  fi
  grep -Fq "Injected ZFS bootstrap failure after $step" "/tmp/nas-zfs-fault-$step.err" || {
    cat "/tmp/nas-zfs-fault-$step.err" >&2
    fail "ZFS bootstrap did not reach injected failure point $step"
  }
  ! zfs list -H tank/nas >/dev/null 2>&1 || {
    zfs list -r tank >&2 || true
    fail "failed ZFS bootstrap after $step left the transient tank/nas dataset behind"
  }
  zfs list -H tank/nas-preserved >/dev/null || fail "fault injection damaged the preserved encryption root"
  if find /run -maxdepth 1 -name 'nas-zfs-bootstrap.*' -type f -print -quit | grep -q .; then
    fail "failed ZFS bootstrap after $step leaked a temporary root key file"
  fi
  pass "failure after $step removes the newly-created encrypted dataset and temporary key"
done
zfs rename tank/nas-preserved tank/nas
ls -la /run/lock/nas-secrets.lock /run/nas-operations/ /run/nas-secret-runtime/ >&2 || true
activate_secrets >/tmp/nas-reactivate-matrix.log 2>&1 || {
  cat /tmp/nas-reactivate-matrix.log >&2 || true
  fail "secret reactivation after fault matrix failed"
}
wait_active nas-protected-services.target
wait_active nas-zfs-unlock.service
wait_active nas-zfs-mount-guard.service
nas-zfs-mount-check
pass "encrypted bootstrap fault matrix preserves and recovers the original dataset"

log "Export and verify the offline recovery key"
rm -f /tmp/nas-zfs-recovery.key
run_as_admin_with_stdin "$(nas_vm_ordinary_wait_seconds)" nas-zfs-export-recovery-key /tmp/nas-zfs-recovery.key
[[ "$(stat -c '%a:%U:%G' /tmp/nas-zfs-recovery.key)" == "400:root:root" ]]
cmp -s /tmp/nas-zfs-recovery.key /run/nas-secrets/zfs/dataset-key
pass "recovery-key export matches the staged KeePassXC key"

log "Lock the dataset and prove reactivation restores it"
wait_reconciliation_idle
run_as_admin nas-zfs-lock
wait_inactive nas-protected-services.target
wait_inactive nas-managed-services-dirty.path
wait_inactive nas-managed-services-reconcile.path
wait_inactive nas-zfs-mount-guard.service
wait_inactive nas-zfs-unlock.service
[[ "$(zfs get -H -o value keystatus tank/nas)" == "unavailable" ]]
[[ "$(zfs get -H -o value mounted tank/nas)" == "no" ]]
[[ ! -e /run/nas-secrets/zfs/dataset-key ]]

activate_secrets
wait_active nas-protected-services.target
nas-zfs-mount-check
[[ "$(zfs get -H -o value keystatus tank/nas)" == "available" ]]
[[ "$(zfs get -H -o value mounted tank/nas)" == "yes" ]]
pass "nas-zfs-lock and secret reactivation complete a full lock/unlock cycle"

systemctl --failed --no-legend --plain | grep -Ev '(^$|nas-health-alert@)' >/tmp/nas-encrypted-failed || true
[[ ! -s /tmp/nas-encrypted-failed ]] || { cat /tmp/nas-encrypted-failed >&2; fail "unexpected failed units remain"; }
printf '\nALL ENCRYPTED ZFS VM TESTS PASSED\n'
