#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE="${NAS_TEST_SOURCE:-/var/lib/nas-test/repo}"
SENTINEL="${NAS_TEST_INSTALL_SENTINEL:-/var/lib/nas-install-test/reinstall-sentinel}"
TIMEOUT="${NAS_TEST_REBUILD_TIMEOUT:-1800}"
PACKAGE_UPGRADE="${NAS_TEST_PACKAGE_UPGRADE:-0}"

log() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
rebuild() {
  timeout --foreground --signal=TERM --kill-after="$(nas_vm_kill_after_seconds)s" \
    "$TIMEOUT" nixos-rebuild "$@" --option warn-dirty false
}
check_doctor() {
  local report="$1" status=0
  nas-doctor --json >"$report" || status=$?
  if [[ "$status" -ne 0 ]]; then
    cat "$report" >&2
    return "$status"
  fi
}

[[ -f "$SOURCE/flake.nix" ]] || fail "reviewed source flake is missing: $SOURCE"
[[ "$(cat "$SENTINEL" 2>/dev/null || true)" == preserve-me ]] || fail "installer persistence sentinel is missing"
[[ "$PACKAGE_UPGRADE" == 0 || "$PACKAGE_UPGRADE" == 1 ]] || fail "invalid package upgrade test mode"

if [[ "$PACKAGE_UPGRADE" == 1 ]]; then
  # shellcheck source=/dev/null
  source "$SOURCE/tests/vm/package-upgrade-baseline.sh"
  log "Promote the initialized older NixOS baseline to the reviewed lock"
  older_version="$(nix eval --raw --override-input nixpkgs "github:NixOS/nixpkgs/$OLDER_NIXPKGS_REV" \
    "path:$SOURCE#nixosConfigurations.nas-qemu.pkgs.syncthing.version")"
  current_version="$(nix eval --raw "path:$SOURCE#nixosConfigurations.nas-qemu.pkgs.syncthing.version")"
  [[ "$older_version" != "$current_version" ]] || fail "older and reviewed Syncthing packages are identical"
  [[ "$older_version" == 2.0.15 ]] || fail "pinned older Syncthing package changed: $older_version"
  baseline_document="$(sha256sum /var/lib/nas-control/services.yaml | cut -d ' ' -f1)"
  baseline_database="$(sha256sum /var/lib/nas-control-plane/nas-secrets/NAS.kdbx | cut -d ' ' -f1)"
  older_system="$(readlink -f /run/current-system)"
  systemctl show --property=ExecStart --value syncthing.service | grep -q "syncthing-$older_version" ||
    fail "installed baseline does not contain the pinned older Syncthing package"
  rebuild switch --flake "path:$SOURCE#nas-qemu"
  [[ "$(readlink -f /run/current-system)" != "$older_system" ]] || fail "upgrade did not activate a distinct generation"
  systemctl show --property=ExecStart --value syncthing.service | grep -q "syncthing-$current_version" ||
    fail "reviewed generation does not contain the newer Syncthing package"
  [[ "$(sha256sum /var/lib/nas-control/services.yaml | cut -d ' ' -f1)" == "$baseline_document" ]] ||
    fail "package upgrade changed the desired-state authority"
  [[ "$(sha256sum /var/lib/nas-control-plane/nas-secrets/NAS.kdbx | cut -d ' ' -f1)" == "$baseline_database" ]] ||
    fail "package upgrade changed the KeePassXC authority"
  [[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "package upgrade destroyed the persistence sentinel"
  check_doctor /tmp/nas-post-package-upgrade-doctor.json
fi

log "Reviewed configuration dry-activate, test, and switch"
rebuild dry-activate --flake "path:$SOURCE#nas-qemu"
rebuild test --flake "path:$SOURCE#nas-qemu"
rebuild switch --flake "path:$SOURCE#nas-qemu"
reviewed_system="$(readlink -f /run/current-system)"
[[ -n "$reviewed_system" ]] || fail "could not identify reviewed system generation"
[[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "reviewed switch destroyed unrelated persistent state"
check_doctor /tmp/nas-post-reconfigure-doctor.json

work="$(mktemp -d /var/tmp/nas-reconfigure-test.XXXXXX)"
trap 'rm -rf "$work"' EXIT

log "Invalid candidate must fail without activation"
cp -a "$SOURCE/." "$work/invalid/"
python3 - "$work/invalid/tests/nixos/qemu-installed.nix" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
pos = text.rfind("\n}")
if pos < 0:
    raise SystemExit("could not locate qemu-installed.nix module terminator")
text = text[:pos] + '''\n  assertions = [ { assertion = false; message = "intentional QEMU rejected-candidate test"; } ];\n''' + text[pos:]
path.write_text(text, encoding="utf-8")
PY
if rebuild test --flake "path:$work/invalid#nas-qemu" >/tmp/nas-invalid-generation.log 2>&1; then
  fail "intentionally invalid candidate unexpectedly activated"
fi
[[ "$(readlink -f /run/current-system)" == "$reviewed_system" ]] || fail "failed candidate changed /run/current-system"
[[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "failed candidate damaged persistent state"
grep -q 'intentional QEMU rejected-candidate test' /tmp/nas-invalid-generation.log || \
  fail "invalid candidate failed for an unexpected reason"

log "Candidate switch and system generation rollback"
cp -a "$SOURCE/." "$work/candidate/"
python3 - "$work/candidate/tests/nixos/qemu-installed.nix" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
pos = text.rfind("\n}")
if pos < 0:
    raise SystemExit("could not locate qemu-installed.nix module terminator")
text = text[:pos] + '''\n  environment.etc."nas-generation-test".text = "candidate-generation\\n";\n''' + text[pos:]
path.write_text(text, encoding="utf-8")
PY
rebuild switch --flake "path:$work/candidate#nas-qemu"
candidate_system="$(readlink -f /run/current-system)"
[[ "$candidate_system" != "$reviewed_system" ]] || fail "candidate did not create a distinct system generation"
grep -qx 'candidate-generation' /etc/nas-generation-test || fail "candidate generation marker is missing"
[[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "candidate switch damaged persistent state"

rebuild --rollback switch --flake "path:$SOURCE#nas-qemu"
[[ "$(readlink -f /run/current-system)" != "$candidate_system" ]] || fail "nixos-rebuild --rollback left candidate active"
[[ ! -e /etc/nas-generation-test ]] || fail "rollback left candidate generation marker active"
[[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "rollback damaged persistent state"

log "Return to the reviewed configuration after rollback drill"
rebuild switch --flake "path:$SOURCE#nas-qemu"
[[ ! -e /etc/nas-generation-test ]] || fail "reviewed generation retained candidate-only marker"
[[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "final reviewed switch damaged persistent state"
check_doctor /tmp/nas-post-rollback-doctor.json
printf '{"ok":true,"invalidCandidateRejected":true,"rollbackVerified":true}\n'
