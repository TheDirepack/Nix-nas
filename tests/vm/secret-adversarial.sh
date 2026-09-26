#!/usr/bin/env bash
set -Eeuo pipefail

KEEPASS_PASSWORD="${NAS_TEST_KEEPASS_PASSWORD:-nixos-nas-vm-test-password}"
DATABASE="${NAS_TEST_KEEPASS_DATABASE:-/var/lib/nas-control-plane/nas-secrets/NAS.kdbx}"
GROUP="${NAS_TEST_KEEPASS_GROUP:-NixOS NAS}"
ADMINISTRATOR_STATE="/var/lib/nas-setup/local-administrator.json"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

[[ -f "$DATABASE" ]] || fail "KeePass database missing: $DATABASE"
[[ -f /run/nas-secrets/ready ]] || fail "runtime secrets are not active before adversarial test"
systemctl is-active --quiet nas-protected-services.target || fail "protected target is not active before adversarial test"
administrator="$(jq -er '.username | select(test("^[a-z_][a-z0-9_-]{0,31}$"))' "$ADMINISTRATOR_STATE")" ||
  fail "configured local administrator is unavailable"
administrator_home="$(getent passwd "$administrator" | cut -d: -f6)"
[[ -n "$administrator_home" && -d "$administrator_home" ]] ||
  fail "configured local administrator home is unavailable"

run_as_administrator() {
  (
    cd "$administrator_home"
    runuser -u "$administrator" -- env HOME="$administrator_home" PATH="$PATH" "$@"
  )
}

activate_secrets_with_retry() {
  local stdout=$1 stderr=$2 rc retries=30
  while ((retries > 0)); do
    if printf '%s\n' "$KEEPASS_PASSWORD" |
      run_as_administrator nas-secrets activate-stdin >"$stdout" 2>"$stderr"; then
      rc=0
    else
      rc=$?
    fi
    if [[ "$rc" -ne 75 ]]; then
      return "$rc"
    fi
    ((retries -= 1))
    sleep 1
  done
  return 75
}

kp_show() {
  local key=$1
  printf '%s\n' "$KEEPASS_PASSWORD" |
    run_as_administrator keepassxc-cli show --quiet --show-protected -a Password \
      "$DATABASE" "$GROUP/$key"
}

kp_set() {
  local key=$1 value=$2
  printf '%s\n%s\n' "$KEEPASS_PASSWORD" "$value" |
    run_as_administrator keepassxc-cli edit --quiet -p "$DATABASE" "$GROUP/$key" >/dev/null
}

runtime_digest() {
  find /run/nas-secrets -type f -print0 |
    sort -z |
    xargs -0 sha256sum |
    sha256sum |
    awk '{print $1}'
}

assert_runtime_unchanged() {
  local before=$1 label=$2 after
  after="$(runtime_digest)"
  [[ "$after" == "$before" ]] || fail "$label changed the committed runtime secret tree"
  [[ -f /run/nas-secrets/ready ]] || fail "$label removed the runtime ready marker"
  systemctl is-active --quiet nas-protected-services.target || fail "$label stopped the protected target"
  for unit in authentik.service authentik-worker.service copyparty.service caddy.service; do
    systemctl is-active --quiet "$unit" || fail "$label left $unit inactive"
  done
}

exercise_rejected_vault_value() {
  local key=$1 malicious=$2 expected=$3 original before rc
  original="$(kp_show "$key")" || fail "unable to read original $key"
  [[ -n "$original" ]] || fail "original $key is empty"
  before="$(runtime_digest)"
  kp_set "$key" "$malicious" || fail "unable to inject adversarial value into $key"
  if activate_secrets_with_retry /tmp/nas-secret-adversarial.out /tmp/nas-secret-adversarial.err; then
    rc=0
  else
    rc=$?
  fi
  if [[ $rc -eq 0 ]]; then
    kp_set "$key" "$original" || true
    fail "activation accepted adversarial KeePass value for $key"
  fi
  grep -Fq "$expected" /tmp/nas-secret-adversarial.err || {
    cat /tmp/nas-secret-adversarial.err >&2
    kp_set "$key" "$original" || true
    fail "activation failure for $key did not identify the unsafe secret format"
  }
  assert_runtime_unchanged "$before" "$key validation failure"
  kp_set "$key" "$original" || fail "unable to restore original $key"
  pass "malformed $key is rejected before runtime secret commit"
}

# keepassxc-cli's password-edit mode is line-oriented, so this installed test uses
# hostile one-line values that can really be written through the CLI. Newline/CR and
# other control-character cases are exercised directly against the rendered validator
# functions in tests/test_secret_security.py.
exercise_rejected_vault_value \
  authentik-secret-key \
  'not-128-hex' \
  "Authentik secret key has an unsafe or unexpected format"

exercise_rejected_vault_value \
  authentik-api-token \
  'safe-api-token;attacker' \
  "Authentik API token has an unsafe or unexpected format"

exercise_rejected_vault_value \
  state-bundle-signing-key \
  'not-64-hex' \
  "State bundle signing key has an unsafe or unexpected format"

exercise_rejected_vault_value \
  ntfy-alert-topic \
  'safe-topic"attacker' \
  "ntfy alert topic has an unsafe or unexpected format"

exercise_rejected_vault_value \
  vaultwarden-oidc-client-secret \
  "safe-client-secret'attacker" \
  "Vaultwarden OIDC client secret has an unsafe or unexpected format"

exercise_rejected_vault_value \
  vaultwarden-admin \
  'safe-admin-token;attacker' \
  "Vaultwarden administrator token has an unsafe or unexpected format"

# The failed attempts must leave no staged secret files behind.
if find /run/nas-secret-runtime/transactions /run/nas-secret-runtime/staging -type f -print -quit 2>/dev/null | grep -q .; then
  fail "failed secret activation left staged secret files behind"
fi

# A clean activation after restoring all KDBX values proves the negative tests did not
# poison the lock, operation coordinator, transaction state, or service lifecycle.
activate_secrets_with_retry \
  /tmp/nas-secret-adversarial-recovery.out /tmp/nas-secret-adversarial-recovery.err || {
  cat /tmp/nas-secret-adversarial-recovery.err >&2
  fail "clean activation after adversarial tests failed"
}
[[ -f /run/nas-secrets/ready ]] || fail "clean activation after adversarial tests did not commit"
systemctl is-active --quiet nas-protected-services.target || fail "protected target did not recover after clean activation"
pass "secret vault corruption tests leave the appliance recoverable"
