#!/usr/bin/env bash

NAS_VM_JS_DEPS_PATH=""
NAS_VM_JS_DEPS_OWNED=0

nas_vm_js_deps_cleanup() {
  local status=${1:-0}
  if ((NAS_VM_JS_DEPS_OWNED == 1)) && [[ -n "$NAS_VM_JS_DEPS_PATH" ]]; then
    rm -rf -- "$NAS_VM_JS_DEPS_PATH"
  fi
  NAS_VM_JS_DEPS_PATH=""
  NAS_VM_JS_DEPS_OWNED=0
  return "$status"
}

nas_vm_js_deps_prepare() {
  local repo=$1 fast_check_path=${2:-} target
  target="$repo/tests/js-fuzz/node_modules"
  [[ ! -e "$target" ]] || {
    printf 'VM suite: dependency directory already exists: %s\n' "$target" >&2
    return 1
  }
  NAS_VM_JS_DEPS_PATH="$target"
  NAS_VM_JS_DEPS_OWNED=1
  mkdir -p "$target"
  if [[ "${NAS_FULL_SUITE_TEST_FAILURE:-}" == after-js-deps-directory ]]; then
    printf 'VM suite: injected failure after dependency directory creation\n' >&2
    return 97
  fi
  if [[ -n "$fast_check_path" ]]; then
    ln -s -- "$fast_check_path" "$target/fast-check"
  else
    npm --prefix "$repo/tests/js-fuzz" ci --no-audit --no-fund
  fi
}
