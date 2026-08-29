#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="${NAS_CONFIG_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
status_file="${NAS_PREFLIGHT_STATUS_FILE:-}"
require_complete="${NAS_PREFLIGHT_REQUIRE_COMPLETE:-0}"
unit_test_timeout="${NAS_UNIT_TEST_TIMEOUT:-180}"
incomplete=()
identity_fixture_lock="${NAS_IDENTITY_LOCK:-}"
fresh_manifest=""

cleanup_preflight() {
  local status=$?
  [[ -z "$fresh_manifest" ]] || rm -f -- "$fresh_manifest"
  if [[ -z "${NAS_IDENTITY_LOCK:-}" && -n "$identity_fixture_lock" ]]; then
    rm -f -- "$identity_fixture_lock"
  fi
  exit "$status"
}

if [[ -z "$identity_fixture_lock" ]]; then
  identity_fixture_lock="$(mktemp "${TMPDIR:-/tmp}/nas-identity-sync-preflight.XXXXXX")"
fi
trap cleanup_preflight EXIT

[[ -d "$repo_root" ]] || { printf 'preflight: missing repository: %s\n' "$repo_root" >&2; exit 1; }
cd -- "$repo_root"

step() {
  printf '\n==> %s\n' "$1"
  shift
  "$@"
}

skip() {
  incomplete+=("$1")
  printf '\nskip: %s\n' "$2"
}

write_status() {
  local result="$1"
  [[ -n "$status_file" ]] || return 0
  python3 - "$status_file" "$result" "${incomplete[@]}" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
payload = {"result": sys.argv[2], "incompleteChecks": sys.argv[3:]}
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

step "repository structure" ./scripts/validate-structure.py
step "V2 architecture boundary" ./scripts/check-architecture-boundary.py
step "version metadata" ./scripts/check-version.py
step "mkForce policy" ./scripts/check-mkforce.py
step "repository data" ./scripts/validate-repository-data.py
step "documentation links" ./scripts/validate-doc-links.py
step "custom executable test inventory" ./scripts/validate-test-inventory.py
step "static security boundaries" ./scripts/security-static-scan.py
step "Python syntax" ./scripts/validate-python-syntax.py

fresh_manifest="$(mktemp "${TMPDIR:-/tmp}/nas-preflight-manifest.XXXXXX")"
step "fresh manifest generation" python3 - "$repo_root" "$fresh_manifest" <<'PY'
from __future__ import annotations

import hashlib
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve()
output = pathlib.Path(sys.argv[2])
ignored_parts = {".git", ".cache", ".hypothesis", ".pytest_cache", "__pycache__", "node_modules", ".direnv", ".venv"}
ignored_names = {".coverage", "coverage.json", "MANIFEST.sha256"}
ignored_suffixes = {".pyc", ".zip", ".qcow2", ".iso", ".log"}

rows = []
for path in sorted(root.rglob("*")):
    relative = path.relative_to(root)
    if any(part in ignored_parts or part.endswith(".egg-info") for part in relative.parts):
        continue
    if relative.name in ignored_names or relative.suffix in ignored_suffixes:
        continue
    mode = path.lstat().st_mode
    if stat.S_ISDIR(mode):
        continue
    if not stat.S_ISREG(mode):
        raise SystemExit(f"fresh manifest encountered non-regular object: {relative}")
    rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{relative.as_posix()}")
output.write_text("\n".join(rows) + "\n", encoding="utf-8")
PY
step "fresh manifest verification" sha256sum --check --status "$fresh_manifest"

# Generated fuzz/property work is deliberately opt-in during preflight. The
# canonical runner owns parallelization and Hypothesis owns input generation;
# preflight must not maintain a second seed/case-count mutation path. Contract
# checks of preflight itself set NAS_PREFLIGHT_SKIP_FUZZ to prevent recursion.
if [[ "${NAS_PREFLIGHT_INCLUDE_FUZZ:-0}" == "1" && "${NAS_PREFLIGHT_SKIP_FUZZ:-0}" != "1" ]]; then
  step "smart fuzz and executable contracts" ./scripts/run-fuzz.py
fi

if [[ "${NAS_PREFLIGHT_SKIP_TESTS:-0}" != "1" ]]; then
  step "Python behavior and contracts" ./scripts/run-unit-tests.py --quiet --timeout "$unit_test_timeout" --jobs "${NAS_UNIT_TEST_JOBS:-4}" \
    --exclude test_maintainer_core.py --exclude test_maintainer_matrix.py --exclude test_maintainer_release.py \
    --exclude test_contract_tooling.py --exclude test_fuzz_boundaries.py --exclude test_property_invariants.py \
    --exclude test_secret_security_fuzz.py
  step "Maintainer core integration tests" ./scripts/run-unit-tests.py --quiet --timeout "$unit_test_timeout" --jobs 1 --pattern 'test_maintainer_core.py'
  step "Maintainer matrix integration tests" ./scripts/run-unit-tests.py --quiet --timeout "$unit_test_timeout" --jobs 1 --pattern 'test_maintainer_matrix.py'
  step "Maintainer release integration tests" ./scripts/run-unit-tests.py --quiet --timeout "$unit_test_timeout" --jobs 1 --pattern 'test_maintainer_release.py'
  step "Tooling contract tests" ./scripts/run-unit-tests.py --quiet --timeout "$unit_test_timeout" --jobs 1 --pattern 'test_contract_tooling.py'
else
  skip python-tests "Python behavior tests disabled by NAS_PREFLIGHT_SKIP_TESTS"
fi

printf '\n==> shell syntax\n'
while IFS= read -r -d '' script; do
  bash -n "$script"
done < <(find scripts tests/vm -type f -name '*.sh' -print0 | sort -z)
printf 'shell syntax ok\n'

if command -v node >/dev/null 2>&1; then
  printf '\n==> JavaScript source, Cockpit bundle, and behavior\n'
  while IFS= read -r -d '' script; do
    node --check "$script"
  done < <(find cockpit/src -type f -name '*.js' -print0 | sort -z)
  while IFS= read -r -d '' script; do
    node --check "$script"
  done < <(find cockpit/e2e tests/js-fuzz -type f -name '*.mjs' -print0 2>/dev/null | sort -z)
  node cockpit/build.js --check-source
  cockpit_bundle_available=false
  if [[ "${NAS_PREFLIGHT_SKIP_COCKPIT_BUNDLE:-0}" == "1" ]]; then
    skip cockpit-bundle "Cockpit distribution validation deferred to the production bundle build"
  elif [[ -s cockpit/package-lock.json && -s cockpit/dist/index.js && -s cockpit/dist/index.css && -s cockpit/dist/build-meta.json ]]; then
    node cockpit/build.js --check
    cockpit_bundle_available=true
  else
    skip cockpit-bundle "React/PatternFly distribution or lockfile is absent; restore the reviewed lockfile, run npm ci, and build the bundle on a controlled builder"
  fi
  if [[ -d cockpit/node_modules/typescript ]] || node -e 'require.resolve("typescript")' >/dev/null 2>&1; then
    node scripts/validate-cockpit-jsx.cjs
  elif $cockpit_bundle_available; then
    printf 'JSX parser check covered by the verified shared Cockpit bundle artifact.\n'
  else
    skip cockpit-jsx-syntax "TypeScript parser unavailable and no verified Cockpit bundle exists"
  fi
  if [[ "${NAS_PREFLIGHT_SKIP_TESTS:-0}" != "1" ]]; then
    node --test tests/js/*.test.mjs
  else
    skip javascript-tests "JavaScript behavior tests disabled by NAS_PREFLIGHT_SKIP_TESTS"
  fi
else
  skip node "Node.js unavailable; CI runs JavaScript checks"
fi

step "Authentik fixture" env PYTHONDONTWRITEBYTECODE=1 NAS_IDENTITY_LOCK="$identity_fixture_lock" \
  python3 services/nas_identity_sync.py status-fixture tests/fixtures/authentik-identity.json

if [[ "${NAS_PREFLIGHT_VERIFY_MANIFEST:-0}" == "1" ]]; then
  manifest_tmp="$(mktemp -d "${TMPDIR:-/tmp}/nas-manifest-preflight.XXXXXX")"
  manifest_path="$manifest_tmp/MANIFEST.sha256"
  export MANIFEST_PATH="$manifest_path"
  export NAS_TEST_MANIFEST="$manifest_path"
  trap 'rm -f -- "$identity_fixture_lock"; rm -rf -- "${manifest_tmp:-}"' EXIT INT TERM HUP
  python3 "$repo_root/scripts/lib/manifest.py" --root "$repo_root" --out "$manifest_path"
  step "release manifest" sha256sum -c "$manifest_path"
fi

if [[ "${NAS_PREFLIGHT_SKIP_TOOLING:-0}" == "1" ]]; then
  skip tooling "Ruff, Pyright, and ShellCheck are owned by dedicated CI steps"
else
  if command -v ruff >/dev/null 2>&1; then
    step "Ruff" ruff check --no-cache services tests scripts
    step "Ruff format" ruff format --check --no-cache services tests scripts
  else
    skip ruff "Ruff unavailable; CI runs it"
  fi

  if command -v pyright >/dev/null 2>&1; then
    step "Pyright" pyright
  else
    skip pyright "Pyright unavailable; CI runs it"
  fi

  if command -v shellcheck >/dev/null 2>&1; then
    mapfile -d '' shell_files < <(find scripts tests/vm -type f -name '*.sh' -print0 | sort -z)
    # Follow explicitly annotated local sources so preflight and the dedicated
    # static CI branch apply the same ShellCheck semantics.
    step "ShellCheck" shellcheck -x "${shell_files[@]}"
  else
    skip shellcheck "ShellCheck unavailable; Nix/CI builds generated shell applications"
  fi
fi

if [[ "${NAS_PREFLIGHT_SKIP_NIX:-0}" == "1" ]]; then
  skip nix "Nix reference configuration evaluation disabled by NAS_PREFLIGHT_SKIP_NIX"
elif command -v nix >/dev/null 2>&1; then
  step "Nix reference configuration evaluation" bash ./scripts/evaluate-reference-configurations.sh
else
  skip nix "Nix unavailable; CI performs reference configuration evaluation and closure builds"
fi

if ((${#incomplete[@]})); then
  write_status partial
  printf '\nPreflight partial: %d check(s) were not executed: %s\n' "${#incomplete[@]}" "${incomplete[*]}"
  if [[ "$require_complete" == "1" ]]; then
    printf 'Complete validation was required.\n' >&2
    exit 2
  fi
else
  write_status passed
  printf '\nPreflight passed completely.\n'
fi
