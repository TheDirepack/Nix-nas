#!/usr/bin/env bash
set -Eeuo pipefail

# Per-application Nix store bundles for the QEMU integration VMs.
#
# The full VM system closure is thousands of store paths. Fetching them one at
# a time through the Magic Nix Cache trips GitHub's per-path cache rate limit
# and can force a from-source build of the entire system. Instead the CI build
# job exports the base NixOS core and each top-level application as one
# archived NAR stream, caches each bundle as a single GitHub Actions entry, and
# the integration job re-imports them before the VM tests build only the small
# system-configuration delta.
#
# Each bundle is keyed by the content-address hash of its flake package output,
# so an unchanged application reuses its previous bundle without a rebuild or
# re-upload. Bundles overlap by design; every imported path is content
# addressed, so duplicate imports are no-ops. `core` is always exported and
# imported first, and every sub-bundle carries only what it adds on top of core.

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SYSTEM="${NAS_BUNDLE_SYSTEM:-x86_64-linux}"
NIX="${NAS_BUNDLE_NIX:-nix}"
NIX_STORE="${NAS_BUNDLE_NIX_STORE:-nix-store}"

# Keep in sync with the `packages.x86_64-linux` attribute set in flake.nix.
BUNDLES=(core copyparty caddy identity observability storage ai test-browser test-tools)

PROG="${0##*/}"

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

usage() {
  cat <<USAGE
usage: $PROG <list|keys|save|import> [dir]

Build, cache, and restore per-application Nix store bundles for the QEMU
integration VMs. Bundle names mirror the packages.x86_64-linux flake output.

  list                 print each bundle name, one per line (core first)
  keys [dir]           print key_<name>=<hash> lines (for GITHUB_OUTPUT) and,
                       when dir is given, write <dir>/<name>.key files
  save <dir>           build every bundle, export each as <dir>/<name>.nar.gz
  import <dir>         gunzip and nix-store --import every bundle, core first

Environment overrides: NAS_BUNDLE_SYSTEM, NAS_BUNDLE_NIX, NAS_BUNDLE_NIX_STORE.
USAGE
}

list_bundles() {
  printf '%s\n' "${BUNDLES[@]}"
}

bundle_out_path() {
  "$NIX" eval --raw ".#packages.$SYSTEM.$1.outPath"
}

bundle_hash() {
  local out
  out=$(bundle_out_path "$1")
  basename "$out" | cut -d- -f1
}

closure() {
  local out
  out=$(bundle_out_path "$1")
  "$NIX" path-info -r "$out" | sort -u
}

keys() {
  local dir=${1:-} name
  while IFS= read -r name; do
    printf 'key_%s=%s\n' "${name//-/_}" "$(bundle_hash "$name")"
    if [[ -n "$dir" ]]; then
      mkdir -p "$dir"
      printf '%s\n' "$(bundle_hash "$name")" > "$dir/$name.key"
    fi
  done < <(list_bundles)
}

save() {
  local dir=$1 name core_file
  mkdir -p "$dir"
  core_file="$dir/.core.paths"

  # Core first: every sub-bundle is the closure "on top of" core.
  "$NIX" build --no-link ".#packages.$SYSTEM.core"
  closure core > "$core_file"
  xargs "$NIX_STORE" --export < "$core_file" | gzip > "$dir/core.nar.gz"

  while IFS= read -r name; do
    [[ $name == core ]] && continue
    "$NIX" build --no-link ".#packages.$SYSTEM.$name"
    comm -23 <(closure "$name") "$core_file" \
      | xargs --no-run-if-empty "$NIX_STORE" --export | gzip > "$dir/$name.nar.gz"
  done < <(list_bundles)

  rm -f "$core_file"
}

import() {
  local dir=$1 name
  while IFS= read -r name; do
    if [[ -f "$dir/$name.nar.gz" ]]; then
      gunzip -c "$dir/$name.nar.gz" | "$NIX_STORE" --import
    fi
  done < <(list_bundles)
}

main() {
  local cmd=${1:-}
  shift || true
  case "$cmd" in
    list) list_bundles ;;
    keys) need "$NIX"; keys "${1:-}" ;;
    save)
      [[ $# -eq 1 ]] || die "save requires exactly one directory argument"
      need "$NIX"
      need "$NIX_STORE"
      need xargs
      save "$1"
      ;;
    import)
      [[ $# -eq 1 ]] || die "import requires exactly one directory argument"
      need "$NIX_STORE"
      need gunzip
      import "$1"
      ;;
    -h | --help | help) usage ;;
    '')
      usage >&2
      exit 2
      ;;
    *) die "unknown subcommand: $cmd" ;;
  esac
}

main "$@"
