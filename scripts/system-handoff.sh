# CI-only helper for exporting the exact installable NixOS system closures.
# Invoke explicitly with `bash`; this file is intentionally not executable.
# shellcheck shell=bash

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit

NIX="${NAS_SYSTEM_HANDOFF_NIX:-nix}"
NIX_STORE_CMD="${NAS_SYSTEM_HANDOFF_NIX_STORE:-nix-store}"
ARCHIVE=system-closures.nar.gz
PATHS=system-closures.paths
DELTA_PATHS=system-closures.delta.paths
CHECKSUM=system-closures.sha256
BUNDLE_MANIFEST=bundle-manifest.tsv
CONFIG_REFS=(
  .#nixosConfigurations.nas-ci-ready.config.system.build.toplevel
  .#nixosConfigurations.nas-qemu.config.system.build.toplevel
)

usage() {
  printf 'usage: bash scripts/system-handoff.sh <save|verify|import> <dir>\n' >&2
}

configuration_out_paths() {
  local ref
  for ref in "${CONFIG_REFS[@]}"; do
    "$NIX" eval --raw "${ref}.outPath"
    printf '\n'
  done
}

bundle_paths() {
  local dir=$1
  awk -F '\t' 'NF == 2 && $2 != "" { print $2 }' "$dir/$BUNDLE_MANIFEST" \
    | LC_ALL=C sort -u
}

first_difference() {
  # Print at most one line while still consuming the complete comm stream. This
  # avoids SIGPIPE surprises under pipefail when the caller only needs evidence
  # that a set difference is non-empty.
  awk 'NR == 1 { first = $0 } END { if (NR != 0) print first }'
}

verify_manifest_coverage() {
  local dir=$1 unexpected overlap missing

  LC_ALL=C sort -c -u "$dir/$PATHS"
  LC_ALL=C sort -c -u "$dir/$DELTA_PATHS"

  unexpected="$({
    LC_ALL=C comm -23 "$dir/$DELTA_PATHS" "$dir/$PATHS"
  } | first_difference)"
  if [[ -n "$unexpected" ]]; then
    printf 'system-handoff: delta contains path outside full system closure: %s\n' \
      "$unexpected" >&2
    return 1
  fi

  overlap="$({
    LC_ALL=C comm -12 "$dir/$DELTA_PATHS" <(bundle_paths "$dir")
  } | first_difference)"
  if [[ -n "$overlap" ]]; then
    printf 'system-handoff: delta duplicates reusable bundle path: %s\n' \
      "$overlap" >&2
    return 1
  fi

  missing="$({
    LC_ALL=C comm -23 "$dir/$PATHS" \
      <({ bundle_paths "$dir"; cat "$dir/$DELTA_PATHS"; } | LC_ALL=C sort -u)
  } | first_difference)"
  if [[ -n "$missing" ]]; then
    printf 'system-handoff: bundle union plus delta does not cover system path: %s\n' \
      "$missing" >&2
    return 1
  fi
}

save_handoff() {
  local dir=$1 archive_tmp
  local -a roots=()
  mkdir -p "$dir"

  [[ -s "$dir/$BUNDLE_MANIFEST" ]] || {
    printf 'system-handoff: reusable bundle manifest is required before system export: %s/%s\n' \
      "$dir" "$BUNDLE_MANIFEST" >&2
    return 1
  }

  printf 'system-handoff: building exact installable system roots\n' >&2
  "$NIX" build --no-link -L "${CONFIG_REFS[@]}"
  mapfile -t roots < <(configuration_out_paths)
  ((${#roots[@]} == ${#CONFIG_REFS[@]}))

  printf 'system-handoff: enumerating complete system closures\n' >&2
  "$NIX" path-info -r "${roots[@]}" | LC_ALL=C sort -u > "$dir/$PATHS"
  [[ -s "$dir/$PATHS" ]]

  # The reusable package/test-driver archives are imported first downstream.
  # Export only the exact system paths they do not already transport; shipping
  # the complete system closure again roughly doubles a multi-gigabyte artifact
  # and can exhaust a standard GitHub-hosted runner while it is being imported.
  LC_ALL=C comm -23 "$dir/$PATHS" <(bundle_paths "$dir") > "$dir/$DELTA_PATHS"

  archive_tmp="$dir/$ARCHIVE.tmp.$$"
  printf 'system-handoff: exporting %s system-only store paths (%s total already covered)\n' \
    "$(wc -l < "$dir/$DELTA_PATHS")" "$(wc -l < "$dir/$PATHS")" >&2
  xargs --no-run-if-empty "$NIX_STORE_CMD" --export < "$dir/$DELTA_PATHS" \
    | gzip -1 -n > "$archive_tmp"
  mv -- "$archive_tmp" "$dir/$ARCHIVE"

  (
    cd -- "$dir"
    sha256sum "$ARCHIVE" "$PATHS" "$DELTA_PATHS" "$BUNDLE_MANIFEST" > "$CHECKSUM"
  )
  verify_handoff "$dir"
}

verify_handoff() {
  local dir=$1
  [[ -s "$dir/$ARCHIVE" ]] || {
    printf 'system-handoff: missing archive: %s/%s\n' "$dir" "$ARCHIVE" >&2
    return 1
  }
  [[ -s "$dir/$PATHS" ]] || {
    printf 'system-handoff: missing path manifest: %s/%s\n' "$dir" "$PATHS" >&2
    return 1
  }
  [[ -e "$dir/$DELTA_PATHS" ]] || {
    printf 'system-handoff: missing delta path manifest: %s/%s\n' "$dir" "$DELTA_PATHS" >&2
    return 1
  }
  [[ -s "$dir/$BUNDLE_MANIFEST" ]] || {
    printf 'system-handoff: missing reusable bundle manifest: %s/%s\n' \
      "$dir" "$BUNDLE_MANIFEST" >&2
    return 1
  }
  [[ -s "$dir/$CHECKSUM" ]] || {
    printf 'system-handoff: missing checksum: %s/%s\n' "$dir" "$CHECKSUM" >&2
    return 1
  }
  (
    cd -- "$dir"
    sha256sum --check --strict --quiet "$CHECKSUM"
  )
  verify_manifest_coverage "$dir"
}

import_handoff() {
  local dir=$1
  verify_handoff "$dir"
  if [[ -s "$dir/$DELTA_PATHS" ]]; then
    printf 'system-handoff: importing exact system-only closure delta\n' >&2
    gzip -dc -- "$dir/$ARCHIVE" | "$NIX_STORE_CMD" --import >/dev/null
  else
    printf 'system-handoff: reusable bundles already cover the exact system closures\n' >&2
  fi

  # The handoff is transport, not runtime state. Once every package bundle and
  # the final system delta have imported successfully, retaining the compressed
  # archives only consumes runner disk needed by QEMU/installer workloads.
  rm -f -- "$dir"/*.nar.gz
}

if (($# != 2)); then
  usage
  exit 2
fi

case "$1" in
  save) save_handoff "$2" ;;
  verify) verify_handoff "$2" ;;
  import) import_handoff "$2" ;;
  *) usage; exit 2 ;;
esac
