#!/usr/bin/env bash
set -Eeuo pipefail

ZFS_DEVICE="${1:-${NAS_TEST_ZFS_DEVICE:-/dev/vdb}}"
KEEPASS_PASSWORD="${NAS_TEST_KEEPASS_PASSWORD:-nixos-nas-vm-test-password}"
TEST_TIMEOUT="${NAS_TEST_TIMEOUT:-$(nas_vm_ordinary_wait_seconds)}"

log() { printf '\n==> %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

on_error() {
  local rc=$?
  printf '\nEncrypted VM validation failed with status %s.\n' "$rc" >&2
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

run_as_admin() {
  runuser -u admin -- env HOME=/home/admin PATH="$PATH" "$@"
}

activate_secrets() {
  run_as_admin_with_stdin "$(nas_vm_timeout_value secretActivation)" nas-secrets activate-stdin
}

run_as_admin_with_stdin() {
  local timeout_seconds=$1
  shift
  nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" \
    runuser -u admin -- env HOME=/home/admin PATH="$PATH" \
      timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" "$timeout_seconds" "$@"
}

log "Verify encrypted fixture starts locked"
wait_active cockpit.socket
[[ ! -e /run/nas-secrets/ready ]] || fail "runtime secrets were unexpectedly active"
! systemctl is-active --quiet nas-protected-services.target || fail "protected services started before unlock"

for _ in $(seq 1 60); do
  [[ -b "$ZFS_DEVICE" ]] && break
  sleep 1
done
[[ -b "$ZFS_DEVICE" ]] || fail "ZFS test disk did not appear: $ZFS_DEVICE"

log "Run first-time setup through the encrypted-ZFS path"
install -d -m 0700 -o admin -g users /var/lib/nas-test/setup
cat >/var/lib/nas-test/setup/encrypted-first-run.json <<EOFSETUP
{
  "schemaVersion": 1,
  "storage": {
    "createPool": true,
    "device": "$ZFS_DEVICE",
    "wipeDevice": true
  },
  "accounts": [],
  "features": {},
  "runPreflight": false
}
EOFSETUP
chown admin:users /var/lib/nas-test/setup/encrypted-first-run.json
chmod 0600 /var/lib/nas-test/setup/encrypted-first-run.json
run_as_admin nas-setup validate-config /var/lib/nas-test/setup/encrypted-first-run.json | jq -e '.storage.createPool == true'
nas_setup_path="$(readlink -f "$(command -v nas-setup)")"
[[ $nas_setup_path == /nix/store/*-nas-setup/bin/nas-setup ]] || fail "nas-setup resolves to unexpected package: $nas_setup_path"
plan_json="$(run_as_admin nas-setup prepare-first-start --config /var/lib/nas-test/setup/encrypted-first-run.json)"
plan_digest="$(jq -er '.planDigest | select(test("^[0-9a-f]{64}$"))' <<<"$plan_json")"
stale_digest="$(printf '0%.0s' {1..64})"
if run_as_admin nas-setup first-run --config /var/lib/nas-test/setup/encrypted-first-run.json \
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
  --config /var/lib/nas-test/setup/encrypted-first-run.json \
  --keepass-password-stdin \
  --confirm-plan-digest "$plan_digest" \
  --confirm-storage-device "$ZFS_DEVICE" \
  --allow-destructive-storage \
  --skip-preflight >/tmp/nas-encrypted-first-run.json
jq -e '
  .database.result == "created" and
  .storage.createdPool == true and
  .storage.createdDataset == true and
  .storage.encrypted == true and
  .preflight == false
' /tmp/nas-encrypted-first-run.json >/dev/null
wait_active nas-protected-services.target
wait_active nas-zfs-unlock.service
wait_active nas-zfs-mount-guard.service
nas-zfs-mount-check
[[ "$(zfs get -H -o value encryptionroot tank/nas)" == "tank/nas" ]]
[[ "$(zfs get -H -o value keyformat tank/nas)" == "hex" ]]
[[ "$(zfs get -H -o value keylocation tank/nas)" == "file:///run/nas-secrets/zfs/dataset-key" ]]
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
run_as_admin nas-zfs-lock
wait_inactive nas-protected-services.target
zfs rename tank/nas tank/nas-preserved
[[ "$(zfs get -H -o value mounted tank/nas-preserved)" == "no" ]]
for step in create keylocation fingerprint canmount unmount unload-key; do
  rm -f "/tmp/nas-zfs-fault-$step.out" "/tmp/nas-zfs-fault-$step.err"
  if nas_vm_run_with_secret_stdin "$KEEPASS_PASSWORD" runuser -u admin -- env HOME=/home/admin PATH="$PATH" \
    NAS_TEST_FAULT_INJECTION=1 NAS_TEST_ZFS_BOOTSTRAP_FAIL_AFTER="$step" \
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
activate_secrets
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
run_as_admin nas-zfs-lock
wait_inactive nas-protected-services.target
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
