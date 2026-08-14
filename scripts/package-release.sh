#!/usr/bin/env bash
set -Eeuo pipefail

source_only=false
output_dir=""
artifact_name=""

usage() {
  echo "Usage: $0 [--source-only] [--name ARTIFACT_NAME] OUTPUT_DIR" >&2
}

while (($#)); do
  case "$1" in
    --source-only) source_only=true ;;
    --name) shift; artifact_name="${1:-}" ;;
    -h|--help) usage; exit 0 ;;
    -*) usage; exit 2 ;;
    *) [[ -z "$output_dir" ]] || { usage; exit 2; }; output_dir="$1" ;;
  esac
  shift
done

[[ -n "$output_dir" ]] || { usage; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"
version="$(tr -d '[:space:]' < VERSION)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9.-]+$ ]] || { echo "Invalid VERSION: $version" >&2; exit 1; }

# VERSION is canonical inside the repository. Human-facing artifact filenames use
# the shorter documented display form. For M.m.0-alpha.N, that is M.m.N.
display_version="$version"
if [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.0-alpha\.([0-9]+)$ ]]; then
  display_version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
fi

archive_root="nixos-nas-$version"
$source_only && archive_root+="-source-only-unverified"
if [[ -z "$artifact_name" ]]; then
  artifact_name="Nix OS NAS $display_version"
  if $source_only; then
    artifact_name+=" source"
  else
    artifact_name+=" release"
  fi
fi
artifact_name_re='^[A-Za-z0-9][A-Za-z0-9._+() -]*$'
[[ "$artifact_name" =~ $artifact_name_re ]] || { echo "Invalid artifact name" >&2; exit 2; }
if $source_only && [[ "$artifact_name" != *source* ]]; then
  echo "Source-only artifact names must include 'source'" >&2
  exit 2
fi

for command in python3 sha256sum; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

if ! $source_only; then
  command -v minisign >/dev/null || { echo "Complete releases require minisign." >&2; exit 1; }
  [[ -n "${NAS_RELEASE_SIGNING_KEY:-}" && -r "${NAS_RELEASE_SIGNING_KEY:-}" ]] || {
    echo "Complete releases require NAS_RELEASE_SIGNING_KEY." >&2
    exit 1
  }
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
status="$work/preflight.json"
stage_root="$work/stage/$archive_root"
mkdir -p "$stage_root"
python3 - "$repo_root" "$stage_root" <<'PY'
from __future__ import annotations

import atexit
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

root = pathlib.Path(sys.argv[1]).resolve()
stage = pathlib.Path(sys.argv[2]).resolve()
known_generated = {
    ".coverage",
    "coverage.json",
}
ignored_parts = {
    ".git",
    ".cache",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    ".direnv",
    ".venv",
    ".hypothesis",
    ".ruff_cache",
    ".mypy_cache",
}
ignored_suffixes = {".pyc", ".zip", ".qcow2", ".iso", ".log"}
ignored_release_suffixes = (".zip.sha256", ".provenance.json")


def ignored(relative: pathlib.PurePath) -> bool:
    if any(part in ignored_parts or part.endswith(".egg-info") for part in relative.parts):
        return True
    if relative.name in known_generated or relative.suffix in ignored_suffixes:
        return True
    return relative.name.endswith(ignored_release_suffixes)

# Reject every symlink and special object in the working tree before selection. This
# prevents ignored paths from being used as an exfiltration side channel.
for path in root.rglob("*"):
    relative = path.relative_to(root)
    if ".git" in relative.parts:
        continue
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise SystemExit(f"release input contains a symlink: {relative}")
    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        raise SystemExit(f"release input contains a non-regular object: {relative}")

git_marker = root / ".git"
git_metadata_matches_root = git_marker.is_dir()
if git_marker.is_file():
    marker = git_marker.read_text(encoding="utf-8").strip()
    if marker.startswith("gitdir: "):
        git_dir = pathlib.Path(marker.removeprefix("gitdir: "))
        if not git_dir.is_absolute():
            git_dir = root / git_dir
        try:
            back_pointer = pathlib.Path((git_dir / "gitdir").read_text(encoding="utf-8").strip())
            if not back_pointer.is_absolute():
                back_pointer = git_dir / back_pointer
            git_metadata_matches_root = back_pointer.resolve() == git_marker.resolve()
        except OSError:
            pass

git_checkout = False
if git_metadata_matches_root:
    try:
        git_root = pathlib.Path(
            subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        ).resolve()
        git_checkout = git_root == root
    except (OSError, subprocess.CalledProcessError):
        pass

if git_checkout:
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if status:
        raise SystemExit("release checkout is dirty or has untracked files; review and commit inputs first")
    payload = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    selected = [pathlib.PurePosixPath(item.decode()) for item in payload.split(b"\0") if item]
    selection_policy = "git-tracked-clean"
else:
    # A non-git tree is authorized by the allowlist that ships inside a source
    # archive. Building the allowlist from the current tree would let an injected
    # file authorize itself, so a tree without a shipped manifest is refused.
    shipped = root / "MANIFEST.sha256"
    if not shipped.is_file():
        raise SystemExit("non-git source tree has no shipped MANIFEST.sha256 allowlist authority")
    _manifest_tmp = tempfile.mkdtemp(prefix="nas-manifest-")
    _manifest_path = pathlib.Path(_manifest_tmp) / "MANIFEST.sha256"
    os.environ["MANIFEST_PATH"] = str(_manifest_path)
    os.environ["NAS_TEST_MANIFEST"] = str(_manifest_path)

    def _cleanup_manifest_tmp() -> None:
        shutil.rmtree(_manifest_tmp, ignore_errors=True)

    atexit.register(_cleanup_manifest_tmp)
    for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(_sig, lambda s, f: (_cleanup_manifest_tmp(), os._exit(128 + s)))  # type: ignore[arg-type]
        except ValueError:
            pass
    # Refresh the per-run manifest with the shared helper so downstream
    # verification is not bound to a stale copy; selection still binds to the
    # shipped allowlist below.
    helper_lib = root / "scripts" / "lib"
    if helper_lib.is_dir():
        sys.path.insert(0, str(helper_lib))
    else:
        sys.path.insert(0, str(pathlib.Path(sys.argv[0]).parent / "scripts" / "lib") if len(sys.argv) > 0 else str(helper_lib))
    try:
        from manifest import generate_manifest  # type: ignore

        generate_manifest(root, _manifest_path)
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"unable to establish release manifest: {exc}") from exc
    shutil.copy(shipped, _manifest_path)
    selected = []
    for line in _manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            raise SystemExit("malformed MANIFEST.sha256 allowlist")
        name = fields[1].lstrip("*")
        if name.startswith("./"):
            name = name[2:]
        selected.append(pathlib.PurePosixPath(name))
    selection_policy = "committed-manifest-allowlist"

normalized: list[pathlib.PurePosixPath] = []
seen: set[str] = set()
for relative in selected:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SystemExit(f"unsafe release allowlist path: {relative}")
    name = relative.as_posix()
    if name == "MANIFEST.sha256" or ignored(relative):
        continue
    if name in seen:
        raise SystemExit(f"duplicate release allowlist path: {name}")
    seen.add(name)
    normalized.append(relative)

actual = {
    path.relative_to(root).as_posix()
    for path in root.rglob("*")
    if stat.S_ISREG(path.lstat().st_mode)
    and path.name != "MANIFEST.sha256"
    and not ignored(path.relative_to(root))
    and ".git" not in path.relative_to(root).parts
}
allowed = {item.as_posix() for item in normalized}
extras = sorted(actual - allowed)
missing = sorted(allowed - actual)
if extras or missing:
    detail = []
    if extras:
        detail.append("unreviewed files: " + ", ".join(extras[:20]))
    if missing:
        detail.append("missing allowlisted files: " + ", ".join(missing[:20]))
    raise SystemExit("release input set differs from its authority: " + "; ".join(detail))

for relative in sorted(normalized, key=lambda value: value.as_posix()):
    source = root.joinpath(*relative.parts)
    mode = source.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise SystemExit(f"release input is not a regular file: {relative}")
    resolved = source.resolve(strict=True)
    if root not in resolved.parents:
        raise SystemExit(f"release input escapes repository: {relative}")
    target = stage.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as reader, target.open("xb") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())
    first_line = target.read_bytes()[:128]
    executable = relative.as_posix() == "cockpit/build.js" or (relative.parts and relative.parts[0] == "scripts" and first_line.startswith(b"#!"))
    os.chmod(target, 0o755 if executable else 0o644)

(stage / ".release-input-policy").write_text(selection_policy + "\n", encoding="utf-8")
PY

# Run expensive validation only after the release input set is proven regular,
# allowlisted, and non-escaping. Unsafe trees fail before unit/security preflight.
if $source_only; then
  NAS_PREFLIGHT_STATUS_FILE="$status" ./scripts/preflight.sh
  validation=source-only
else
  NAS_PREFLIGHT_REQUIRE_COMPLETE=1 NAS_PREFLIGHT_STATUS_FILE="$status" ./scripts/preflight.sh
  validation=complete
fi

if ! $source_only; then
  evidence_dir="${NAS_RELEASE_EVIDENCE_DIR:-}"
  [[ -n "$evidence_dir" && -d "$evidence_dir" ]] || {
    echo "Complete releases require NAS_RELEASE_EVIDENCE_DIR with qemu and installer evidence." >&2
    exit 1
  }
  python3 - "$evidence_dir" "$stage_root/release-evidence" "$repo_root" <<'PY'
from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess
import sys

source = pathlib.Path(sys.argv[1]).resolve()
target = pathlib.Path(sys.argv[2]).resolve()
repo = pathlib.Path(sys.argv[3]).resolve()
required = {
    "qemu/commit.txt",
    "qemu/checks.txt",
    "installer/commit.txt",
    "installer/checks.txt",
}
actual = set()
for path in source.rglob("*"):
    relative = path.relative_to(source).as_posix()
    mode = path.lstat().st_mode
    if stat.S_ISDIR(mode):
        continue
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise SystemExit(f"release evidence contains a non-regular object: {relative}")
    actual.add(relative)
if actual != required:
    raise SystemExit(f"release evidence set mismatch: expected {sorted(required)}, got {sorted(actual)}")
commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
for name in ("qemu/commit.txt", "installer/commit.txt"):
    recorded = (source / name).read_text(encoding="utf-8").strip()
    if recorded != commit:
        raise SystemExit(f"release evidence {name} belongs to {recorded}, not {commit}")
for name in sorted(required):
    src = source / name
    dst = target / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as reader, dst.open("xb") as writer:
        shutil.copyfileobj(reader, writer)
        writer.flush()
        os.fsync(writer.fileno())
    os.chmod(dst, 0o644)
for directory in sorted((path for path in target.rglob("*") if path.is_dir()), reverse=True):
    os.chmod(directory, 0o755)
os.chmod(target, 0o755)
PY
fi

python3 "$repo_root/scripts/lib/manifest.py" --root "$stage_root" --out "$stage_root/MANIFEST.sha256"
selection_policy="$(tr -d '\r\n' < "$stage_root/.release-input-policy")"
case "$selection_policy" in
  git-tracked-clean|committed-manifest-allowlist) ;;
  *) echo "Invalid release input selection policy" >&2; exit 1 ;;
esac
rm -f "$stage_root/.release-input-policy"

(
  cd "$stage_root"
  sha256sum -c MANIFEST.sha256 >/dev/null
  NAS_CONFIG_DIR="$stage_root" NAS_PREFLIGHT_VERIFY_MANIFEST=1 NAS_PREFLIGHT_SKIP_TESTS=1 ./scripts/preflight.sh >/dev/null
)

archive="$work/$artifact_name.zip"
python3 - "$stage_root" "$archive" "$archive_root" <<'PY'
from __future__ import annotations

import pathlib
import stat
import sys
import zipfile

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
prefix = pathlib.PurePosixPath(sys.argv[3])
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise SystemExit(f"staged archive input is not regular: {relative}")
        info = zipfile.ZipInfo(str(prefix / pathlib.PurePosixPath(relative.as_posix())))
        info.date_time = (2026, 1, 1, 0, 0, 0)
        info.external_attr = (stat.S_IFREG | (stat.S_IMODE(mode) & 0o777)) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, path.read_bytes())
PY

archive_hash="$(sha256sum "$archive" | awk '{print $1}')"
printf '%s  %s.zip\n' "$archive_hash" "$artifact_name" > "$work/$artifact_name.zip.sha256"
cp "$stage_root/MANIFEST.sha256" "$work/$artifact_name.MANIFEST.sha256"
manifest_hash="$(sha256sum "$stage_root/MANIFEST.sha256" | awk '{print $1}')"
flake_hash="$(sha256sum "$stage_root/flake.lock" | awk '{print $1}')"
commit=unavailable
if [[ "$selection_policy" == git-tracked-clean ]]; then
  commit="$(git rev-parse HEAD)"
  NAS_RELEASE_GIT_TREE="$(git rev-parse 'HEAD^{tree}')"
  export NAS_RELEASE_GIT_TREE
  selection_policy=git-tracked-clean
fi
python3 "$repo_root/scripts/lib/release_provenance.py" \
  --out "$work/$artifact_name.provenance.json" \
  --version "$version" \
  --artifact-name "$artifact_name" \
  --archive-root "$archive_root" \
  --validation "$validation" \
  --archive-hash "$archive_hash" \
  --manifest-hash "$manifest_hash" \
  --flake-hash "$flake_hash" \
  --commit "$commit" \
  --selection-policy "$selection_policy" \
  --status "$status" \
  --stage-root "$stage_root" \
  --git-tree "${NAS_RELEASE_GIT_TREE:-unavailable}"

python3 -m zipfile -t "$archive" >/dev/null
python3 - "$archive" "$stage_root" "$archive_root" <<'PY'
from __future__ import annotations

import hashlib
import pathlib
import stat
import sys
import tempfile
import zipfile

archive_path = pathlib.Path(sys.argv[1])
staged = pathlib.Path(sys.argv[2])
prefix = pathlib.PurePosixPath(sys.argv[3])
expected = {path.relative_to(staged).as_posix() for path in staged.rglob("*") if stat.S_ISREG(path.lstat().st_mode)}
with zipfile.ZipFile(archive_path) as archive:
    names = []
    for member in archive.infolist():
        path = pathlib.PurePosixPath(member.filename)
        if path.is_absolute() or not path.parts or path.parts[0] != prefix.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
            raise SystemExit(f"unsafe archive member: {member.filename}")
        mode = (member.external_attr >> 16) & 0o170000
        if mode not in {0, stat.S_IFREG} or member.is_dir():
            raise SystemExit(f"archive contains non-regular member: {member.filename}")
        relative = pathlib.PurePosixPath(*path.parts[1:])
        staged_mode = stat.S_IMODE((staged / relative.as_posix()).lstat().st_mode) & 0o777
        archived_mode = (member.external_attr >> 16) & 0o777
        if archived_mode != staged_mode:
            raise SystemExit(
                f"archive mode mismatch for {relative}: archived={archived_mode:o} staged={staged_mode:o}"
            )
        names.append(relative.as_posix())
    if set(names) != expected or len(names) != len(expected):
        raise SystemExit("archive file set does not exactly match staged release")
    manifest_rows = {}
    text = archive.read(str(prefix / "MANIFEST.sha256")).decode()
    for line in text.splitlines():
        digest, name = line.split(maxsplit=1)
        manifest_rows[name.removeprefix("./")] = digest
    expected_manifest = expected - {"MANIFEST.sha256"}
    if set(manifest_rows) != expected_manifest:
        extras = sorted(set(manifest_rows) - expected_manifest)
        missing = sorted(expected_manifest - set(manifest_rows))
        raise SystemExit(f"archive manifest mismatch: extras={extras[:20]}, missing={missing[:20]}")
    for name, digest in manifest_rows.items():
        actual = hashlib.sha256(archive.read(str(prefix / name))).hexdigest()
        if actual != digest:
            raise SystemExit(f"archive manifest mismatch: {name}")
PY

if ! $source_only; then
  minisign -S -s "$NAS_RELEASE_SIGNING_KEY" -m "$work/$artifact_name.provenance.json" -x "$work/$artifact_name.provenance.json.minisig"
fi

mkdir -p "$output_dir"
publish_tmp="$output_dir/.${archive_root}.release.$$"
publish_final="$output_dir/${archive_root}.release"
[[ ! -e "$publish_final" ]] || { echo "Release destination already exists: $publish_final" >&2; exit 1; }
mkdir "$publish_tmp"
for suffix in zip zip.sha256 provenance.json MANIFEST.sha256; do
  install -m 0644 "$work/$artifact_name.$suffix" "$publish_tmp/$artifact_name.$suffix"
done
if ! $source_only; then
  install -m 0644 "$work/$artifact_name.provenance.json.minisig" "$publish_tmp/$artifact_name.provenance.json.minisig"
fi
python3 - "$publish_tmp" <<'PY'
import os
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for path in root.iterdir():
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
mv "$publish_tmp" "$publish_final"
printf 'Published %s atomically to %s\n' "$artifact_name" "$publish_final"
