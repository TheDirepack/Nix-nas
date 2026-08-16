#!/usr/bin/env bash
set -Eeuo pipefail

# Reusable Nix store bundles for the QEMU integration VMs.
#
# The full VM system closure is thousands of store paths. Fetching them one at
# a time through the Magic Nix Cache trips GitHub's per-path cache rate limit
# and can force a from-source build of the entire system. Instead the CI build
# job exports the boot/unlock base and each optional application as archived NAR
# streams, caches each bundle as a single GitHub Actions entry, and the
# integration job re-imports them before the VM tests build only the small
# system-configuration delta.
#
# Each bundle is keyed by the content-address hash of every root it contains,
# so an unchanged bundle reuses its previous archive without a rebuild or
# re-upload. `core` contains boot, recovery, unlock, primary access, and
# deterministic-test package roots. The application bundles contain the
# identity, observability, storage-add-on, and AI package roots. `vm-drivers`
# carries the exact unencrypted and encrypted NixOS test-driver roots. Their
# generated driver configurations reference each VM's system.build.vm start
# script, so only this config-sensitive bundle changes when the appliance
# configuration changes.
#
# Application archives are deltas against the `core` closure. The driver
# archive is a delta against the union of core and every application closure so
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
BUNDLES=(core identity observability storage ai vm-drivers)

PROG="${0##*/}"

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"; }

usage() {
  cat <<USAGE
usage: $PROG <list|keys|save|save-missing|verify|verify-partial-handoff|verify-handoff|import> [dir]

Build, cache, and restore reusable Nix store bundles for the QEMU integration
VMs. The core bundle contains boot/unlock and common test packages; application
bundles remain separate, and vm-drivers additionally includes both NixOS VM
test drivers.

  list                 print each bundle name, one per line (core first)
  keys [dir]           print key_<name>=<hash> lines (for GITHUB_OUTPUT) and,
                       when dir is given, write <dir>/<name>.key files
  build [bundle ...]   build selected bundle roots, or every root when omitted
  save <dir>           build every bundle, export each as <dir>/<name>.nar.gz
  save-missing <dir>   build every bundle, export only archives absent in <dir>
  verify <dir>         verify the generated manifest has no closure duplicates
  verify-partial-handoff <dir>
                       verify a missing-only handoff artifact
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
  printf '%s: building bundle roots: %s\n' "$PROG" "${*}" >&2
  "$NIX" build --no-link -L "${refs[@]}"
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
  local dir=$1 only_missing=${2:-0} name core_file application_file base_file manifest archive tmp
  local closure_cache
  local -a targets=()
  mkdir -p "$dir"
  closure_cache="$(mktemp -d "$dir/.closure-cache.XXXXXX")"
  # Closure enumeration is expensive and is needed by the delta exporter and
  # the manifest writer. Keep one result per bundle for the duration of this
  # handoff, then remove the run-owned cache even if export fails.
  SAVE_CLOSURE_CACHE=$closure_cache
  trap 'if [[ -n ${SAVE_CLOSURE_CACHE:-} ]]; then rm -rf -- "$SAVE_CLOSURE_CACHE"; fi' EXIT
  core_file="$dir/.core.paths"
  application_file="$dir/.application.paths"
  base_file="$dir/.base.paths"
  manifest="$dir/bundle-manifest.tsv"

  closure_cached() {
    local cached_name=$1 cached_file="$SAVE_CLOSURE_CACHE/$1.paths"
    if [[ ! -f "$cached_file" ]]; then
      if [[ -f "$dir/$cached_name.paths" ]]; then
        printf '%s: reusing cached closure manifest for %s\n' "$PROG" "$cached_name" >&2
        cp -- "$dir/$cached_name.paths" "$cached_file"
        sort -u "$cached_file" -o "$cached_file"
      else
        printf '%s: enumerating closure for %s\n' "$PROG" "$cached_name" >&2
        closure "$cached_name" > "$cached_file"
        printf '%s: closure enumeration complete for %s (%s paths)\n' \
          "$PROG" "$cached_name" "$(wc -l < "$cached_file")" >&2
      fi
    fi
    cat "$cached_file"
  }

  write_manifest() {
    local manifest_name manifest_path
    : > "$manifest"
    while IFS= read -r manifest_name; do
      case "$manifest_name" in
        core) closure_cached core > "$dir/.manifest.paths" ;;
        vm-drivers) comm -23 <(closure_cached vm-drivers) "$base_file" > "$dir/.manifest.paths" ;;
        *) comm -23 <(closure_cached "$manifest_name") "$core_file" > "$dir/.manifest.paths" ;;
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
      closure_cached core > "$core_file"
      : > "$application_file"
      while IFS= read -r name; do
        [[ $name == core || $name == vm-drivers ]] && continue
        closure_cached "$name"
      done < <(list_bundles) | sort -u > "$application_file"
      cat "$core_file" "$application_file" | sort -u > "$base_file"
      write_manifest
      rm -f "$core_file" "$application_file" "$base_file"
    }
    verify_manifest "$dir"
    write_handoff_checksum "$dir"
    return 0
  fi

  # Submit only missing bundle roots together so Nix can schedule their shared
  # DAG once. Export order remains core-first and each archive keeps the same
  # delta shape.
  if [[ ${NAS_BUNDLE_SKIP_BUILD:-0} == 1 ]]; then
    printf '%s: reusing bundle roots built by the preceding CI build step\n' "$PROG" >&2
  else
    build_bundles "${targets[@]}"
  fi
  closure_cached core > "$core_file"
  : > "$application_file"
  while IFS= read -r name; do
    [[ $name == core || $name == vm-drivers ]] && continue
    closure_cached "$name"
  done < <(list_bundles) | sort -u > "$application_file"
  cat "$core_file" "$application_file" | sort -u > "$base_file"
  closure_cached vm-drivers > /dev/null
  while IFS= read -r name; do
    cp -- "$SAVE_CLOSURE_CACHE/$name.paths" "$dir/$name.paths"
  done < <(list_bundles)

  export_bundle() {
    local export_name=$1 export_paths=$2 export_archive=$3 export_tmp=$4
    local path_count
    local heartbeat_pid
    local -a export_status
    path_count="$(wc -l < "$export_paths")"
    printf '%s: exporting %s bundle (%s store paths)\n' \
      "$PROG" "$export_name" "$path_count" >&2
    # The heartbeat is a separate process group so its sleep child cannot
    # keep the exporter pipe open after the export finishes.
    # shellcheck disable=SC2016
    setsid --wait bash -c '
      while sleep 30; do
        elapsed=$(( $(date +%s) - $4 ))
        printf "%s: still exporting %s (%s store paths, %ss elapsed)\\n" "$1" "$2" "$3" "$elapsed" >&2
      done
    ' bundle-export-heartbeat "$PROG" "$export_name" "$path_count" "$(( $(date +%s) ))" &
    heartbeat_pid=$!
    set +e
    # These archives are disposable cache transport, not release artifacts.
    # Fast deterministic compression keeps a cold handoff from spending most
    # of its time compressing data that Nix will checksum and cache again.
    xargs --no-run-if-empty "$NIX_STORE_CMD" --export < "$export_paths" | gzip -1 -n > "$export_tmp"
    export_status=("${PIPESTATUS[@]}")
    set -e
    kill -- "-$heartbeat_pid" 2>/dev/null || kill -KILL "$heartbeat_pid" 2>/dev/null || true
    wait "$heartbeat_pid" 2>/dev/null || true
    if (( export_status[0] != 0 || export_status[1] != 0 )); then
      die "failed to export $export_name bundle (nix-store=${export_status[0]}, gzip=${export_status[1]})"
    fi
    mv -- "$export_tmp" "$export_archive"
  }

  if [[ $only_missing != 1 || ! -f "$dir/core.nar.gz" ]]; then
    archive="$dir/core.nar.gz"
    tmp="$archive.tmp.$$"
    export_bundle core "$core_file" "$archive" "$tmp"
  fi

  while IFS= read -r name; do
    [[ $name == core ]] && continue
    [[ $only_missing == 1 && -f "$dir/$name.nar.gz" ]] && continue
    archive="$dir/$name.nar.gz"
    tmp="$archive.tmp.$$"
    if [[ $name == vm-drivers ]]; then
      comm -23 <(closure_cached "$name") "$base_file" > "$dir/.export.paths"
    else
      comm -23 <(closure_cached "$name") "$core_file" > "$dir/.export.paths"
    fi
    export_bundle "$name" "$dir/.export.paths" "$archive" "$tmp"
  done < <(list_bundles)

  write_manifest
  verify_manifest "$dir"
  write_handoff_checksum "$dir"
  rm -f "$core_file" "$application_file" "$base_file" "$dir/.export.paths"
  rm -rf -- "$closure_cache"
  SAVE_CLOSURE_CACHE=
  trap - EXIT
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
        # Application closures may share transitive dependencies. The driver
        # delta must not, because it is explicitly exported against the union
        # of core and every application closure.
        if (owners[path] ~ /(^| )vm-drivers( |$)/) {
          printf "duplicate driver bundle closure path: %s (%s)\n", path, owners[path] > "/dev/stderr"
          bad = 1
        }
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

verify_partial_handoff() {
  local dir=$1 archive
  [[ -f "$dir/bundle-manifest.tsv" ]] || die "bundle manifest is missing: $dir/bundle-manifest.tsv"
  [[ -f "$dir/bundle-handoff.partial.sha256" ]] || die "partial bundle checksum is missing: $dir/bundle-handoff.partial.sha256"
  archive=0
  for path in "$dir"/*.nar.gz; do
    [[ -f "$path" ]] || continue
    archive=1
  done
  ((archive == 1)) || die "partial bundle handoff contains no archives: $dir"
  (
    cd -- "$dir"
    sha256sum --check --strict --quiet bundle-handoff.partial.sha256
  ) || die "partial bundle handoff checksum validation failed: $dir"
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
    build)
      need "$NIX"
      if (($# == 0)); then
        build_bundles "${BUNDLES[@]}"
      else
        for name in "$@"; do
          case "$name" in
            core|identity|observability|storage|ai|vm-drivers) ;;
            *) die "unknown bundle: $name" ;;
          esac
        done
        build_bundles "$@"
      fi
      ;;
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
    verify-partial-handoff)
      [[ $# -eq 1 ]] || die "verify-partial-handoff requires exactly one directory argument"
      need sha256sum
      verify_partial_handoff "$1"
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
