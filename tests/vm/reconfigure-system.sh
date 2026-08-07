#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE="${NAS_TEST_SOURCE:-/var/lib/nas-test/repo}"
SENTINEL="${NAS_TEST_INSTALL_SENTINEL:-/var/lib/nas-install-test/reinstall-sentinel}"
TIMEOUT="${NAS_TEST_REBUILD_TIMEOUT:-1800}"

log() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
rebuild() { timeout --foreground "$TIMEOUT" nixos-rebuild "$@" --option warn-dirty false; }

[[ -f "$SOURCE/flake.nix" ]] || fail "reviewed source flake is missing: $SOURCE"
[[ "$(cat "$SENTINEL" 2>/dev/null || true)" == preserve-me ]] || fail "installer persistence sentinel is missing"

log "Reviewed configuration dry-activate, test, and switch"
rebuild dry-activate --flake "path:$SOURCE#nas-qemu"
rebuild test --flake "path:$SOURCE#nas-qemu"
rebuild switch --flake "path:$SOURCE#nas-qemu"
reviewed_system="$(readlink -f /run/current-system)"
[[ -n "$reviewed_system" ]] || fail "could not identify reviewed system generation"
[[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "reviewed switch destroyed unrelated persistent state"
nas-doctor --json >/tmp/nas-post-reconfigure-doctor.json

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

rebuild switch --rollback
[[ "$(readlink -f /run/current-system)" != "$candidate_system" ]] || fail "nixos-rebuild --rollback left candidate active"
[[ ! -e /etc/nas-generation-test ]] || fail "rollback left candidate generation marker active"
[[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "rollback damaged persistent state"

log "Return to the reviewed configuration after rollback drill"
rebuild switch --flake "path:$SOURCE#nas-qemu"
[[ ! -e /etc/nas-generation-test ]] || fail "reviewed generation retained candidate-only marker"
[[ "$(cat "$SENTINEL")" == preserve-me ]] || fail "final reviewed switch damaged persistent state"
nas-doctor --json >/tmp/nas-post-rollback-doctor.json
printf '{"ok":true,"invalidCandidateRejected":true,"rollbackVerified":true}\n'
