# CI-only helper for exporting the exact installable NixOS system closures.
# Invoke explicitly with `bash`; this file is intentionally not executable.
# shellcheck shell=bash

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit

NIX="${NAS_SYSTEM_HANDOFF_NIX:-nix}"
NIX_STORE_CMD="${NAS_SYSTEM_HANDOFF_NIX_STORE:-nix-store}"
ARCHIVE=system-closures.nar.gz
EXPORTS=system-closures.exports
EXPORT_ORDER=system-closures.delta.import-order
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
  [[ -f "$dir/$EXPORT_ORDER" ]] || return 1
  # Export ordering is a permutation of the delta, with no duplicates.
  [[ "$(wc -l < "$dir/$EXPORT_ORDER")" -eq "$(wc -l < "$dir/$DELTA_PATHS")" ]] || return 1
  LC_ALL=C sort -u "$dir/$EXPORT_ORDER" | cmp - "$dir/$DELTA_PATHS"

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

# Each archive is one complete nix-store --export stream, independently
# importable. Bound argv count so larger closures never exceed ARG_MAX.
export_delta_batch() {
  local dir=$1 index=$2 name archive_tmp
  shift 2
  if ((index == 0)); then
    name=$ARCHIVE
  else
    printf -v name 'system-closures.part-%06d.nar.gz' "$index"
  fi
  archive_tmp="$dir/$name.tmp.$"
  "$NIX_STORE_CMD" --export "$@" | gzip -1 -n > "$archive_tmp"
  mv -- "$archive_tmp" "$dir/$name"
  printf '%s\n' "$name" >> "$dir/$EXPORTS"
}

verify_export_manifest() {
  local dir=$1 line expected index=0
  [[ -s "$dir/$EXPORTS" ]] || {
    printf 'system-handoff: missing export stream manifest\n' >&2
    return 1
  }
  while IFS= read -r line; do
    if ((index == 0)); then
      expected=$ARCHIVE
    else
      printf -v expected 'system-closures.part-%06d.nar.gz' "$index"
    fi
    [[ "$line" == "$expected" && -s "$dir/$line" ]] || {
      printf 'system-handoff: missing or out-of-order export stream: %s\n' "$expected" >&2
      return 1
    }
    index=$((index + 1))
  done < "$dir/$EXPORTS"
  ((index > 0))
}

# Print the requisites of the given paths that no reusable bundle, earlier
# shard, already accepted path in this shard (extra_allowed), or the paths
# themselves already transport.
shard_missing_requisites() {
  local dir=$1 extra_allowed=$2
  shift 2
  local closure="$dir/$EXPORT_ORDER.requisites"
  local allowed="$dir/$EXPORT_ORDER.allowed"
  local -a chunk=()
  local path

  : > "$closure"
  for path in "$@"; do
    chunk+=("$path")
    if ((${#chunk[@]} == 128)); then
      "$NIX_STORE_CMD" --query --requisites "${chunk[@]}" >> "$closure" || return 1
      chunk=()
    fi
  done
  if ((${#chunk[@]})); then
    "$NIX_STORE_CMD" --query --requisites "${chunk[@]}" >> "$closure" || return 1
  fi
  {
    bundle_paths "$dir"
    cat -- "$dir/$EXPORT_ORDER.exported"
    if [[ -n "$extra_allowed" ]]; then
      cat -- "$extra_allowed"
    fi
    printf '%s\n' "$@"
  } | LC_ALL=C sort -u > "$allowed"
  LC_ALL=C sort -u "$closure" | LC_ALL=C comm -23 - "$allowed"
}

shard_cleanup() {
  local dir=$1
  rm -f -- "$dir/$EXPORT_ORDER".{exported,batch,missing,requisites,allowed}
}

# nix-store --import rejects a path whose requisites are not already in the
# store, and every shard is imported as one independent export stream. The
# requisites order is only a candidate: accept each path into the current shard
# only once its requisites are transported by a bundle, an earlier shard, or
# this shard. A path and its dependencies therefore always travel in the same
# or an earlier shard, and the export shards are exactly the planned shards.
export_delta_shards() {
  local dir=$1
  local -a pending=() batch=() kept=()
  local path index=0

  mapfile -t pending < "$dir/$EXPORT_ORDER"
  : > "$dir/$EXPORT_ORDER"
  : > "$dir/$EXPORT_ORDER.exported"
  : > "$dir/$EXPORT_ORDER.batch"
  : > "$dir/$EXPORTS"
  while ((${#pending[@]})); do
    batch=("${pending[@]:0:128}")
    if ! shard_missing_requisites "$dir" "" "${batch[@]}" > "$dir/$EXPORT_ORDER.missing"; then
      shard_cleanup "$dir"
      return 1
    fi
    if [[ -s "$dir/$EXPORT_ORDER.missing" ]]; then
      # The candidate order put requisites behind their requester: rebuild this
      # shard path by path so the 128-path bound is kept and every accepted
      # path is already importable.
      batch=()
      kept=()
      : > "$dir/$EXPORT_ORDER.batch"
      for path in "${pending[@]}"; do
        if ((${#batch[@]} == 128)); then
          kept+=("$path")
          continue
        fi
        if ! shard_missing_requisites "$dir" "$dir/$EXPORT_ORDER.batch" "$path" \
          > "$dir/$EXPORT_ORDER.missing"; then
          shard_cleanup "$dir"
          return 1
        fi
        if [[ -s "$dir/$EXPORT_ORDER.missing" ]]; then
          kept+=("$path")
        else
          batch+=("$path")
          printf '%s\n' "$path" >> "$dir/$EXPORT_ORDER.batch"
        fi
      done
      pending=("${kept[@]}")
      if ((${#batch[@]} == 0)); then
        printf 'system-handoff: no importable export shard left in the requisites order\n' >&2
        shard_cleanup "$dir"
        return 1
      fi
    else
      pending=("${pending[@]:128}")
    fi
    export_delta_batch "$dir" "$index" "${batch[@]}"
    printf '%s\n' "${batch[@]}" >> "$dir/$EXPORT_ORDER"
    printf '%s\n' "${batch[@]}" >> "$dir/$EXPORT_ORDER.exported"
    index=$((index + 1))
  done
  if ((index == 0)); then
    gzip -1 -n </dev/null > "$dir/$ARCHIVE"
    printf '%s\n' "$ARCHIVE" >> "$dir/$EXPORTS"
  fi
  shard_cleanup "$dir"
}

save_handoff() {
  local dir=$1
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

  # Nix requisites are emitted with dependencies first; use that as the
  # candidate import order rather than filesystem/alphabetical path order, then
  # let export_delta_shards prove every shard is importable on its own.
  "$NIX_STORE_CMD" --query --requisites "${roots[@]}" \
    | awk 'FILENAME == ARGV[1] { wanted[$0] = 1; next }
           $0 in wanted { print; delete wanted[$0] }
           END { for (path in wanted) { print "unreachable export: " path > "/dev/stderr"; failed = 1 }
                 if (failed) exit 1 }' "$dir/$DELTA_PATHS" - \
    > "$dir/$EXPORT_ORDER"

  printf 'system-handoff: exporting %s system-only store paths (%s total already covered)\n' \
    "$(wc -l < "$dir/$DELTA_PATHS")" "$(wc -l < "$dir/$PATHS")" >&2
  export_delta_shards "$dir"

  (
    cd -- "$dir"
    sha256sum "$PATHS" "$DELTA_PATHS" "$BUNDLE_MANIFEST" "$EXPORTS" "$EXPORT_ORDER" > "$CHECKSUM"
    while IFS= read -r path; do
      sha256sum "$path" >> "$CHECKSUM"
    done < "$EXPORTS"
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
  verify_export_manifest "$dir"
  # sha256sum --check validates listed entries, not completeness of the list.
  local filename line
  local -A required=()
  for filename in "$PATHS" "$DELTA_PATHS" "$BUNDLE_MANIFEST" "$EXPORTS" "$EXPORT_ORDER"; do
    required["$filename"]=1
  done
  while IFS= read -r filename; do
    required["$filename"]=1
  done < "$dir/$EXPORTS"
  while IFS= read -r line; do
    if [[ ! "$line" =~ ^[[:xdigit:]]{64}[[:space:]][[:space:]]([^[:space:]]+)$ ]]; then
      printf 'system-handoff: malformed checksum record\n' >&2
      return 1
    fi
    filename="${BASH_REMATCH[1]}"
    if [[ -z "${required[$filename]+present}" ]]; then
      printf 'system-handoff: duplicate or unexpected checksum for %s\n' "$filename" >&2
      return 1
    fi
    unset 'required[$filename]'
  done < "$dir/$CHECKSUM"
  if ((${#required[@]})); then
    printf 'system-handoff: missing checksum entry for required handoff file\n' >&2
    return 1
  fi
  (
    cd -- "$dir"
    sha256sum --check --strict --quiet "$CHECKSUM"
  )
  verify_manifest_coverage "$dir"
}

verify_imported_delta() {
  local dir=$1 path
  local -a batch=()
  while IFS= read -r path; do
    batch+=("$path")
    if ((${#batch[@]} == 128)); then
      "$NIX" path-info "${batch[@]}" >/dev/null
      batch=()
    fi
  done < "$dir/$DELTA_PATHS"
  if ((${#batch[@]})); then
    "$NIX" path-info "${batch[@]}" >/dev/null
  fi
}

import_handoff() {
  local dir=$1
  verify_handoff "$dir"
  if [[ -s "$dir/$DELTA_PATHS" ]]; then
    printf 'system-handoff: importing exact system-only closure delta\n' >&2
    local name
    while IFS= read -r name; do
      gzip -dc -- "$dir/$name" | "$NIX_STORE_CMD" --import >/dev/null
    done < "$dir/$EXPORTS"
    # A successful import command is insufficient evidence on its own:
    # verify every promised delta path exists before deleting the transport.
    verify_imported_delta "$dir"
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
