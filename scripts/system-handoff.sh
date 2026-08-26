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
CHECKSUM=system-closures.sha256
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

save_handoff() {
  local dir=$1 archive_tmp
  local -a roots=()
  mkdir -p "$dir"

  printf 'system-handoff: building exact installable system roots\n' >&2
  "$NIX" build --no-link -L "${CONFIG_REFS[@]}"
  mapfile -t roots < <(configuration_out_paths)
  ((${#roots[@]} == ${#CONFIG_REFS[@]}))

  printf 'system-handoff: enumerating complete system closures\n' >&2
  "$NIX" path-info -r "${roots[@]}" | sort -u > "$dir/$PATHS"
  [[ -s "$dir/$PATHS" ]]

  archive_tmp="$dir/$ARCHIVE.tmp.$$"
  printf 'system-handoff: exporting %s store paths\n' "$(wc -l < "$dir/$PATHS")" >&2
  xargs --no-run-if-empty "$NIX_STORE_CMD" --export < "$dir/$PATHS" \
    | gzip -1 -n > "$archive_tmp"
  mv -- "$archive_tmp" "$dir/$ARCHIVE"

  (
    cd -- "$dir"
    sha256sum "$ARCHIVE" "$PATHS" > "$CHECKSUM"
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
  [[ -s "$dir/$CHECKSUM" ]] || {
    printf 'system-handoff: missing checksum: %s/%s\n' "$dir" "$CHECKSUM" >&2
    return 1
  }
  (
    cd -- "$dir"
    sha256sum --check --strict --quiet "$CHECKSUM"
  )
}

import_handoff() {
  local dir=$1
  verify_handoff "$dir"
  printf 'system-handoff: importing exact installable system closure archive\n' >&2
  gzip -dc -- "$dir/$ARCHIVE" | "$NIX_STORE_CMD" --import >/dev/null
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
