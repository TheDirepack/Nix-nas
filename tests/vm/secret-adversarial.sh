#!/usr/bin/env bash
set -Eeuo pipefail

KEEPASS_PASSWORD="${NAS_TEST_KEEPASS_PASSWORD:-nixos-nas-vm-test-password}"
DATABASE="${NAS_TEST_KEEPASS_DATABASE:-/var/lib/nas-secrets/NAS.kdbx}"
GROUP="${NAS_TEST_KEEPASS_GROUP:-NixOS NAS}"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

[[ -f "$DATABASE" ]] || fail "KeePass database missing: $DATABASE"
[[ -f /run/nas-secrets/ready ]] || fail "runtime secrets are not active before adversarial test"
systemctl is-active --quiet nas-protected-services.target || fail "protected target is not active before adversarial test"

kp_show() {
  local key=$1
  printf '%s\n' "$KEEPASS_PASSWORD" |
    runuser -u admin -- keepassxc-cli show --quiet --pw-stdin --show-protected -a Password \
      "$DATABASE" "$GROUP/$key"
}

kp_set() {
  local key=$1 value=$2
  printf '%s\n%s\n' "$KEEPASS_PASSWORD" "$value" |
    runuser -u admin -- keepassxc-cli edit --quiet --pw-stdin -p "$DATABASE" "$GROUP/$key" >/dev/null
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
  set +e
  printf '%s\n' "$KEEPASS_PASSWORD" |
    runuser -u admin -- env HOME=/home/admin PATH="$PATH" nas-secrets activate-stdin \
      >/tmp/nas-secret-adversarial.out 2>/tmp/nas-secret-adversarial.err
  rc=$?
  set -e
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
  authentik-bootstrap-password \
  'safe-password value' \
  "Authentik bootstrap password has an unsafe or unexpected format"

exercise_rejected_vault_value \
  llama-swap-api-key \
  'safe-api-key;attacker' \
  "llama-swap API key has an unsafe or unexpected format"

exercise_rejected_vault_value \
  ntfy-alert-topic \
  'safe-topic"attacker' \
  "ntfy alert topic has an unsafe or unexpected format"

exercise_rejected_vault_value \
  vaultwarden-oidc-client-secret \
  "safe-client-secret'attacker" \
  "Vaultwarden OIDC client secret has an unsafe or unexpected format"

# The failed attempts must leave no staged secret files behind.
if find /run/nas-secret-transactions /run/nas-secret-staging -type f -print -quit 2>/dev/null | grep -q .; then
  fail "failed secret activation left staged secret files behind"
fi

# A clean activation after restoring all KDBX values proves the negative tests did not
# poison the lock, operation coordinator, transaction state, or service lifecycle.
printf '%s\n' "$KEEPASS_PASSWORD" |
  runuser -u admin -- env HOME=/home/admin PATH="$PATH" nas-secrets activate-stdin \
    >/tmp/nas-secret-adversarial-recovery.out
[[ -f /run/nas-secrets/ready ]] || fail "clean activation after adversarial tests did not commit"
systemctl is-active --quiet nas-protected-services.target || fail "protected target did not recover after clean activation"
pass "secret vault corruption tests leave the appliance recoverable"
