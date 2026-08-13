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
# Each bundle is keyed by the content-address hash of every root it contains,
# so an unchanged bundle reuses its previous archive without a rebuild or
# re-upload. Most bundles have one packages.<system> root. `vm-drivers` carries
# the exact unencrypted and encrypted NixOS test-driver roots. Their generated
# driver configurations reference each VM's system.build.vm start script, so
# only this config-sensitive bundle changes when the appliance configuration
# changes.
#
# Every non-core archive is a delta against the `core` closure. Normally core
# is restored and imported first. GitHub cache entries can be evicted or saved
# independently, though, so a consumer may see a later delta without the core
# archive. In that case import builds/fetches the exact current core root first
# and only then imports the restored deltas; partial cache state must never be
# allowed to feed nix-store --import with missing base paths.

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SYSTEM="${NAS_BUNDLE_SYSTEM:-x86_64-linux}"
NIX="${NAS_BUNDLE_NIX:-nix}"
NIX_STORE_CMD="${NAS_BUNDLE_NIX_STORE:-nix-store}"

# Keep in sync with the `packages.x86_64-linux` attribute set in flake.nix.
BUNDLES=(core copyparty caddy identity observability storage ai test-browser test-tools vm-drivers)

PROG="${0##*/}"

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

usage() {
  cat <<USAGE
usage: $PROG <list|keys|save|save-missing|import> [dir]

Build, cache, and restore per-application Nix store bundles for the QEMU
integration VMs. Bundle names mirror the packages.x86_64-linux flake output;
the vm-drivers bundle additionally includes both NixOS VM test drivers.

  list                 print each bundle name, one per line (core first)
  keys [dir]           print key_<name>=<hash> lines (for GITHUB_OUTPUT) and,
                       when dir is given, write <dir>/<name>.key files
  save <dir>           build every bundle, export each as <dir>/<name>.nar.gz
  save-missing <dir>   build every bundle, export only archives absent in <dir>
  import <dir>         restore core (or rebuild it) then import cached deltas

Environment overrides: NAS_BUNDLE_SYSTEM, NAS_BUNDLE_NIX, NAS_BUNDLE_NIX_STORE.
USAGE
}

list_bundles() {
  printf '%s\n' "${BUNDLES[@]}"
}

bundle_refs() {
  local name=$1
  printf '.#packages.%s.%s\n' "$SYSTEM" "$name"
  if [[ $name == vm-drivers ]]; then
    printf '.#checks.%s.nas-vm.driver\n' "$SYSTEM"
    printf '.#checks.%s.nas-vm-encrypted.driver\n' "$SYSTEM"
  fi
}

bundle_out_paths() {
  local ref
  while IFS= read -r ref; do
    "$NIX" eval --raw "${ref}.outPath"
    printf '\n'
  done < <(bundle_refs "$1")
}

bundle_hash() {
  local name=$1 out
  local -a hashes=()
  if [[ $name != core ]]; then
    while IFS= read -r out; do
      if [[ -n $out ]]; then
        hashes+=("$(basename "$out" | cut -d- -f1)")
        break
      fi
    done < <(bundle_out_paths core)
  fi
  while IFS= read -r out; do
    hashes+=("$(basename "$out" | cut -d- -f1)")
  done < <(bundle_out_paths "$name")
  (IFS=-; printf '%s\n' "${hashes[*]}")
}

closure() {
  local -a outs=()
  mapfile -t outs < <(bundle_out_paths "$1")
  "$NIX" path-info -r "${outs[@]}" | sort -u
}

build_all_bundles() {
  local name ref
  local -a refs=()
  while IFS= read -r name; do
    while IFS= read -r ref; do
      refs+=("$ref")
    done < <(bundle_refs "$name")
  done < <(list_bundles)
  "$NIX" build --no-link "${refs[@]}"
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
  local dir=$1 only_missing=${2:-0} name core_file
  mkdir -p "$dir"
  core_file="$dir/.core.paths"

  # Submit all bundle roots together so Nix can schedule their shared DAG once.
  # Export order remains core-first and each archive keeps the same delta shape.
  build_all_bundles
  closure core > "$core_file"
  if [[ $only_missing != 1 || ! -f "$dir/core.nar.gz" ]]; then
  xargs "$NIX_STORE_CMD" --export < "$core_file" | gzip > "$dir/core.nar.gz"
  fi

  while IFS= read -r name; do
    [[ $name == core ]] && continue
    [[ $only_missing == 1 && -f "$dir/$name.nar.gz" ]] && continue
    comm -23 <(closure "$name") "$core_file" \
      | xargs --no-run-if-empty "$NIX_STORE_CMD" --export | gzip > "$dir/$name.nar.gz"
  done < <(list_bundles)

  rm -f "$core_file"
}

import() {
  local dir=$1 name

  if [[ -f "$dir/core.nar.gz" ]]; then
    gunzip -c "$dir/core.nar.gz" | "$NIX_STORE_CMD" --import
  else
    printf '%s: core bundle archive is unavailable; building exact core base before cached deltas\n' "$PROG" >&2
    "$NIX" build --no-link ".#packages.$SYSTEM.core"
  fi

  while IFS= read -r name; do
    [[ $name == core ]] && continue
    if [[ -f "$dir/$name.nar.gz" ]]; then
      gunzip -c "$dir/$name.nar.gz" | "$NIX_STORE_CMD" --import
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
      need "$NIX_STORE_CMD"
      need xargs
      save "$1"
      ;;
    save-missing)
      [[ $# -eq 1 ]] || die "save-missing requires exactly one directory argument"
      need "$NIX"
      need "$NIX_STORE_CMD"
      need xargs
      save "$1" 1
      ;;
    import)
      [[ $# -eq 1 ]] || die "import requires exactly one directory argument"
      need "$NIX"
      need "$NIX_STORE_CMD"
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
