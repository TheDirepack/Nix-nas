#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="${NAS_CONFIG_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
status_file="${NAS_PREFLIGHT_STATUS_FILE:-}"
require_complete="${NAS_PREFLIGHT_REQUIRE_COMPLETE:-0}"
incomplete=()

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
step "version metadata" ./scripts/check-version.py
step "mkForce policy" ./scripts/check-mkforce.py
step "repository data" ./scripts/validate-repository-data.py
step "documentation links" ./scripts/validate-doc-links.py
step "custom executable test inventory" ./scripts/validate-test-inventory.py
step "static security boundaries" ./scripts/security-static-scan.py
step "Python syntax" ./scripts/validate-python-syntax.py

# Fuzzing is deliberately opt-in. CI owns long-running fuzz/property work in
# the final slow stage, after static checks, builds, runtime integration, and
# final-system deterministic qualification have succeeded.
if [[ "${NAS_PREFLIGHT_INCLUDE_FUZZ:-0}" == "1" ]]; then
  step "deterministic boundary fuzz smoke" ./scripts/fuzz.py --cases "${NAS_PREFLIGHT_FUZZ_CASES:-250}"
  step "custom executable fuzz smoke" ./scripts/fuzz-executables.py --cases "${NAS_PREFLIGHT_EXECUTABLE_FUZZ_CASES:-1}"
fi

if [[ "${NAS_PREFLIGHT_SKIP_TESTS:-0}" != "1" ]]; then
  step "Python behavior and contracts" ./scripts/run-unit-tests.py --quiet --jobs "${NAS_UNIT_TEST_JOBS:-4}" \
    --exclude test_maintainer_core.py --exclude test_maintainer_matrix.py --exclude test_maintainer_release.py \
    --exclude test_contract_tooling.py --exclude test_fuzz_boundaries.py --exclude test_property_invariants.py
  step "Maintainer core integration tests" ./scripts/run-unit-tests.py --quiet --jobs 1 --pattern 'test_maintainer_core.py'
  step "Maintainer matrix integration tests" ./scripts/run-unit-tests.py --quiet --jobs 1 --pattern 'test_maintainer_matrix.py'
  step "Maintainer release integration tests" ./scripts/run-unit-tests.py --quiet --jobs 1 --pattern 'test_maintainer_release.py'
  step "Tooling contract tests" ./scripts/run-unit-tests.py --quiet --jobs 1 --pattern 'test_contract_tooling.py'
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
  done < <(find cockpit/e2e -type f -name '*.mjs' -print0 2>/dev/null | sort -z)
  node cockpit/build.js --check-source
  cockpit_bundle_available=false
  if [[ -s cockpit/package-lock.json && -s cockpit/dist/index.js && -s cockpit/dist/index.css && -s cockpit/dist/build-meta.json ]]; then
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

step "Authentik fixture" env PYTHONDONTWRITEBYTECODE=1 python3 services/nas_identity_sync.py status-fixture tests/fixtures/authentik-identity.json

if [[ "${NAS_PREFLIGHT_VERIFY_MANIFEST:-0}" == "1" ]]; then
  [[ -f MANIFEST.sha256 ]] || { printf 'preflight: MANIFEST.sha256 is required\n' >&2; exit 1; }
  step "release manifest" sha256sum -c MANIFEST.sha256
fi

if command -v ruff >/dev/null 2>&1; then
  step "Ruff" ruff check services tests scripts
  step "Ruff format" ruff format --check services tests scripts
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
  step "ShellCheck" shellcheck "${shell_files[@]}"
else
  skip shellcheck "ShellCheck unavailable; Nix/CI builds generated shell applications"
fi

if [[ "${NAS_PREFLIGHT_SKIP_NIX:-0}" == "1" ]]; then
  skip nix "Nix flake evaluation disabled by NAS_PREFLIGHT_SKIP_NIX"
elif command -v nix >/dev/null 2>&1; then
  step "Nix flake evaluation" nix flake check --no-build --show-trace
else
  skip nix "Nix unavailable; CI performs flake evaluation and closure builds"
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
