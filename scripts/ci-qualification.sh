# Shared implementation for the parallel CI qualification branches.
# This file is invoked explicitly with `bash`; it is intentionally not a shipped executable.
# shellcheck shell=bash

set -u -o pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

section=${1:-}
if [[ -z "$section" ]]; then
  printf 'usage: bash scripts/ci-qualification.sh <shared|static|unit|security|nonroot|cockpit>\n' >&2
  exit 2
fi

mkdir -p ci-logs
: > "ci-logs/${section}-results.tsv"
export CI_LOG_DIR=ci-logs
export CI_RESULTS_FILE="ci-logs/${section}-results.tsv"
source .github/ci-checks.sh
failed=0

case "$section" in
  shared)
    ci_run shared preflight "Source-only repository preflight" env \
      NAS_PREFLIGHT_SKIP_TESTS=1 \
      NAS_PREFLIGHT_SKIP_COCKPIT_BUNDLE=1 \
      NAS_PREFLIGHT_SKIP_TOOLING=1 \
      NAS_PREFLIGHT_SKIP_NIX=1 \
      ./scripts/preflight.sh || failed=1
    ci_run shared python-syntax "Python syntax inventory" \
      ./scripts/validate-python-syntax.py || failed=1
    ci_run shared test-inventory "Test inventory contract" \
      nix develop .#test -c python3 scripts/validate-test-inventory.py || failed=1

    check_shell_syntax() {
      local rc=0 script
      while IFS= read -r -d '' script; do
        bash -n "$script" || rc=1
      done < <(find scripts tests/vm -type f -name '*.sh' -print0)
      bash -n .github/ci-checks.sh || rc=1
      return "$rc"
    }
    ci_run shared shell-syntax "Shell syntax" check_shell_syntax || failed=1
    ;;

  static)
    ci_run static secret-faults "Secret transaction fault injection" \
      nix develop .#test -c bats tests/bats || failed=1
    ci_run static shellcheck "ShellCheck" \
      nix develop .#test -c shellcheck \
      .github/ci-checks.sh scripts/*.sh scripts/lib/*.sh tests/vm/*.sh || failed=1
    ci_run static actionlint "GitHub Actions lint" \
      nix develop .#test -c actionlint \
      .github/workflows/ci.yml .github/workflows/release.yml || failed=1
    ci_run static ruff-check "Python lint" \
      nix develop .#test -c ruff check services tests scripts || failed=1
    ci_run static ruff-format "Python formatting" \
      nix develop .#test -c ruff format --check services tests scripts || failed=1
    ci_run static pyright "Python types" \
      nix develop .#test -c pyright --project pyproject.toml || failed=1
    ci_run static prettier "JavaScript formatting" \
      nix develop .#test -c prettier --check \
      "cockpit/src/**/*.{js,jsx,scss}" "cockpit/e2e/*.mjs" \
      "tests/js/*.mjs" prettier.config.mjs || failed=1
    ci_run static nix-matrix "Nix configuration matrix" \
      ./scripts/nix-config-matrix.sh || failed=1
    ci_run static reference-eval "Reference configuration evaluation" \
      ./scripts/evaluate-reference-configurations.sh || failed=1
    ;;

  unit)
    ci_run unit fast-python "Fast Python unit tests" \
      nix develop .#test -c ./scripts/run-unit-tests.py \
      --coverage coverage.json --quiet --jobs 4 \
      --exclude test_maintainer_core.py \
      --exclude test_maintainer_matrix.py \
      --exclude test_maintainer_release.py \
      --exclude test_contract_tooling.py \
      --exclude test_fuzz_boundaries.py \
      --exclude test_property_invariants.py \
      --exclude test_secret_security_fuzz.py || failed=1

    check_coverage_floor() {
      if [[ ! -s coverage.json ]]; then
        echo "coverage.json was not produced by the fast unit suite"
        return 2
      fi
      nix develop .#test -c python3 scripts/check-coverage.py \
        coverage.json --total-floor 66
    }
    ci_run unit coverage-floor "Coverage floor" check_coverage_floor || failed=1

    for contract in \
      test_maintainer_core.py \
      test_maintainer_matrix.py \
      test_maintainer_release.py \
      test_contract_tooling.py
    do
      slug=${contract%.py}
      ci_run unit "$slug" "Maintainer contract: $contract" \
        nix develop .#test -c ./scripts/run-unit-tests.py \
        --jobs 1 --pattern "$contract" || failed=1
    done
    ;;

  security)
    ci_run security regressions "Deterministic security regression suite" \
      nix develop .#test -c ./scripts/run-security-tests.py || failed=1
    ci_run security semgrep "Semgrep local rules" \
      nix develop .#test -c semgrep --config .semgrep.yml --error \
      services scripts cockpit/src web || failed=1
    ci_run security bandit "Bandit privileged runtime scan" \
      nix develop .#test -c bandit -q -c .bandit -r services scripts -ll -ii || failed=1
    ci_run security caddy "Caddy generator validation" \
      nix develop .#test -c python3 -m unittest \
      tests.test_v2_caddy tests.test_v2_caddy_validate -v || failed=1
    ;;

  nonroot)
    run_nonroot_suite() {
      local nix_bin
      : "${GITHUB_WORKSPACE:?GitHub workspace is required}"
      nix_bin=$(command -v nix)
      sudo useradd --create-home --shell /bin/bash nas-ci
      sudo install -d -o nas-ci -g nas-ci /home/nas-ci/worktree
      sudo cp -a "$GITHUB_WORKSPACE/." /home/nas-ci/worktree/
      sudo chown -R nas-ci:nas-ci /home/nas-ci/worktree
      sudo -u nas-ci env HOME=/home/nas-ci TMPDIR=/tmp \
        bash -c "cd /home/nas-ci/worktree && exec \"$nix_bin\" develop .#test -c ./scripts/run-unit-tests.py --jobs 4 --exclude test_maintainer_core.py --exclude test_maintainer_matrix.py --exclude test_maintainer_release.py --exclude test_contract_tooling.py --exclude test_fuzz_boundaries.py --exclude test_property_invariants.py --exclude test_secret_security_fuzz.py"
    }
    ci_run nonroot fast-suite "Run the fast suite without root-owned state" \
      run_nonroot_suite || failed=1
    ;;

  cockpit)
    check_cockpit_js_syntax() {
      local rc=0 script
      for script in cockpit/src/*.js; do
        node --check "$script" || rc=1
      done
      return "$rc"
    }
    ci_run cockpit js-syntax "Cockpit JavaScript syntax" \
      check_cockpit_js_syntax || failed=1
    ci_run cockpit source-contract "Cockpit source renderer contract" \
      node cockpit/build.js --check-source || failed=1
    ci_run cockpit jsx "Cockpit JSX validation" \
      node scripts/validate-cockpit-jsx.cjs || failed=1
    ci_run cockpit unit-tests "Cockpit unit tests" \
      node --test tests/js/*.test.mjs || failed=1
    ci_run cockpit npm-audit "Fresh npm vulnerability audit" \
      npm --prefix cockpit audit --audit-level=high || failed=1
    ci_run cockpit build "Production Cockpit bundle" \
      npm --prefix cockpit run build || failed=1
    ci_run cockpit build-check "Production Cockpit bundle verification" \
      node cockpit/build.js --check || failed=1
    ;;

  *)
    printf 'unknown CI qualification section: %s\n' "$section" >&2
    exit 2
    ;;
esac

exit "$failed"
