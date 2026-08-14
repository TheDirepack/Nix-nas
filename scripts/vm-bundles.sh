#!/usr/bin/env bash
set -Eeuo pipefail

# Reusable Nix store bundles for the QEMU integration VMs.
#
# The full VM system closure is thousands of store paths. Fetching them one at
# a time through the Magic Nix Cache trips GitHub's per-path cache rate limit
# and can force a from-source build of the entire system. Instead the CI build
# job exports the complete reusable package base as one archived NAR stream,
# caches it as a single GitHub Actions entry, and the integration job
# re-imports it before the VM tests build only the small system-configuration
# delta.
#
# Each bundle is keyed by the content-address hash of every root it contains,
# so an unchanged bundle reuses its previous archive without a rebuild or
# re-upload. `core` contains the package roots used by the appliance and all
# deterministic VM tests. `vm-drivers` carries the exact unencrypted and
# encrypted NixOS test-driver roots. Their generated driver configurations
# reference each VM's system.build.vm start script, so only this
# config-sensitive bundle changes when the appliance configuration changes.
#
# The driver archive is a delta against the complete `core` closure, so
# configuration-sensitive test drivers do not duplicate package paths.
# Normally core is restored and imported first. GitHub cache entries can be
# evicted or saved independently, though, so a consumer may see the driver
# delta without the core archive. In that case import builds/fetches the exact
# current core root first and only then imports the restored delta; partial
# cache state must never be allowed to feed nix-store --import with missing base
# paths.

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SYSTEM="${NAS_BUNDLE_SYSTEM:-x86_64-linux}"
NIX="${NAS_BUNDLE_NIX:-nix}"
NIX_STORE_CMD="${NAS_BUNDLE_NIX_STORE:-nix-store}"

# Keep in sync with the reusable roots in `packages.x86_64-linux` in flake.nix.
BUNDLES=(core vm-drivers)

PROG="${0##*/}"

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

usage() {
  cat <<USAGE
usage: $PROG <list|keys|save|save-missing|verify|verify-handoff|import> [dir]

Build, cache, and restore reusable Nix store bundles for the QEMU integration
VMs. The core bundle contains all appliance and deterministic-test packages;
the vm-drivers bundle additionally includes both NixOS VM test drivers.

  list                 print each bundle name, one per line (core first)
  keys [dir]           print key_<name>=<hash> lines (for GITHUB_OUTPUT) and,
                       when dir is given, write <dir>/<name>.key files
  save <dir>           build every bundle, export each as <dir>/<name>.nar.gz
  save-missing <dir>   build every bundle, export only archives absent in <dir>
  verify <dir>         verify the generated manifest has no closure duplicates
  verify-handoff <dir> verify every archive checksum and the closure manifest
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

build_bundles() {
  local name ref
  local -a refs=()
  for name in "$@"; do
    while IFS= read -r ref; do
      refs+=("$ref")
    done < <(bundle_refs "$name")
  done
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
  local dir=$1 only_missing=${2:-0} name core_file base_file manifest archive tmp
  local -a targets=()
  mkdir -p "$dir"
  core_file="$dir/.core.paths"
  base_file="$dir/.base.paths"
  manifest="$dir/bundle-manifest.tsv"

  write_manifest() {
    local manifest_name manifest_path
    : > "$manifest"
    while IFS= read -r manifest_name; do
      case "$manifest_name" in
        core) closure core > "$dir/.manifest.paths" ;;
        vm-drivers) comm -23 <(closure vm-drivers) "$base_file" > "$dir/.manifest.paths" ;;
        *) die "unknown bundle in manifest: $manifest_name" ;;
      esac
      while IFS= read -r manifest_path; do
        [[ -n "$manifest_path" ]] && printf '%s\t%s\n' "$manifest_name" "$manifest_path" >> "$manifest"
      done < "$dir/.manifest.paths"
    done < <(list_bundles)
    rm -f "$dir/.manifest.paths"
  }

  if [[ $only_missing == 1 ]]; then
    while IFS= read -r name; do
      [[ -f "$dir/$name.nar.gz" ]] || targets+=("$name")
    done < <(list_bundles)
  else
    targets=("${BUNDLES[@]}")
  fi
  # A complete cache hit is already the exact handoff needed by downstream
  # VMs. Do not invoke Nix or rewrite archives when there is nothing missing.
  if ((${#targets[@]} == 0)); then
    [[ -f "$dir/bundle-manifest.tsv" ]] || {
      closure core > "$core_file"
      cp "$core_file" "$base_file"
      write_manifest
      rm -f "$core_file" "$base_file"
    }
    verify_manifest "$dir"
    write_handoff_checksum "$dir"
    return 0
  fi

  # Submit only missing bundle roots together so Nix can schedule their shared
  # DAG once. Export order remains core-first and each archive keeps the same
  # delta shape.
  build_bundles "${targets[@]}"
  closure core > "$core_file"
  cp "$core_file" "$base_file"
  if [[ $only_missing != 1 || ! -f "$dir/core.nar.gz" ]]; then
    archive="$dir/core.nar.gz"
    tmp="$archive.tmp.$$"
    xargs "$NIX_STORE_CMD" --export < "$core_file" | gzip > "$tmp"
    mv -- "$tmp" "$archive"
  fi

  name=vm-drivers
  if [[ $only_missing != 1 || ! -f "$dir/$name.nar.gz" ]]; then
    archive="$dir/$name.nar.gz"
    tmp="$archive.tmp.$$"
    comm -23 <(closure "$name") "$base_file" \
      | xargs --no-run-if-empty "$NIX_STORE_CMD" --export | gzip > "$tmp"
    mv -- "$tmp" "$archive"
  fi

  write_manifest
  verify_manifest "$dir"
  write_handoff_checksum "$dir"
  rm -f "$core_file" "$base_file"
}

verify_manifest() {
  local dir=$1 manifest
  manifest="$dir/bundle-manifest.tsv"
  [[ -f "$manifest" ]] || die "bundle manifest is missing: $manifest"
  awk -F '\t' '
    NF != 2 || $1 == "" || $2 == "" { bad = 1; next }
    seen[$2]++
    owners[$2] = owners[$2] " " $1
    END {
      for (path in seen) if (seen[path] != 1) {
        printf "duplicate bundle closure path: %s (%s)\n", path, owners[path] > "/dev/stderr"
        bad = 1
      }
      exit bad
    }
  ' "$manifest" || die "bundle manifest contains duplicate or malformed closure paths"
}

write_handoff_checksum() {
  local dir=$1 name
  local -a files=()
  for name in "${BUNDLES[@]}"; do
    files+=("$name.nar.gz")
  done
  (
    cd -- "$dir"
    sha256sum "${files[@]}" bundle-manifest.tsv > bundle-handoff.sha256
  ) || die "could not write bundle handoff checksum: $dir"
}

verify_handoff() {
  local dir=$1 name
  local -a files=()
  for name in "${BUNDLES[@]}"; do
    files+=("$dir/$name.nar.gz")
  done
  [[ -f "$dir/bundle-manifest.tsv" ]] || die "bundle manifest is missing: $dir/bundle-manifest.tsv"
  [[ -f "$dir/bundle-handoff.sha256" ]] || die "bundle handoff checksum is missing: $dir/bundle-handoff.sha256"
  for name in "${files[@]}"; do
    [[ -f "$name" ]] || die "bundle archive is missing: $name"
  done
  (
    cd -- "$dir"
    sha256sum --check --strict --quiet bundle-handoff.sha256
  ) || die "bundle handoff checksum validation failed: $dir"
  verify_manifest "$dir"
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
      need sha256sum
      save "$1"
      ;;
    save-missing)
      [[ $# -eq 1 ]] || die "save-missing requires exactly one directory argument"
      need "$NIX"
      need "$NIX_STORE_CMD"
      need xargs
      need sha256sum
      save "$1" 1
      ;;
    verify)
      [[ $# -eq 1 ]] || die "verify requires exactly one directory argument"
      verify_manifest "$1"
      ;;
    verify-handoff)
      [[ $# -eq 1 ]] || die "verify-handoff requires exactly one directory argument"
      need sha256sum
      verify_handoff "$1"
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
