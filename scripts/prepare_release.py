"""Prepare one release commit from a merge checkout.

The GitHub release workflow invokes this module with ``python3``. It keeps the
release-specific mutations in one tested place: patch-version stamping,
bootstrap-password rotation, and synchronized release metadata.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import secrets
import subprocess
from dataclasses import dataclass

VERSION_RE = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)$")
BOOTSTRAP_RE = re.compile(r'store_value authentik-bootstrap-password "([^"\n]+)"')
SAFE_SECRET_RE = re.compile(r"^[A-Za-z0-9._~+/=:@-]+$")
BOOTSTRAP_USERNAME = "akadmin"
CORE_BOOTSTRAP_PATHS = {
    "modules/nas/internal/secret-tools.nix",
    "modules/nas/config/application-services.nix",
}


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: str) -> "Version":
        match = VERSION_RE.fullmatch(value.strip())
        if match is None:
            raise ValueError(f"automatic releases require a three-component numeric VERSION, got {value!r}")
        return cls(*(int(match.group(name)) for name in ("major", "minor", "patch")))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


def run_git(root: pathlib.Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=check,
    )


def matching_tags(root: pathlib.Path, version: Version) -> list[tuple[str, int]]:
    result = run_git(root, "tag", "--list", f"v{version.major}.{version.minor}.*")
    pattern = re.compile(rf"^v{version.major}\.{version.minor}\.([0-9]+)$")
    tags: list[tuple[str, int]] = []
    for line in result.stdout.splitlines():
        tag = line.strip()
        match = pattern.fullmatch(tag)
        if match is not None:
            tags.append((tag, int(match.group(1))))
    return tags


def version_already_released_from_source(root: pathlib.Path, current: Version, source_sha: str) -> Version | None:
    for tag, patch in sorted(matching_tags(root, current), key=lambda item: item[1], reverse=True):
        parent = run_git(root, "rev-parse", f"{tag}^{{commit}}^1", check=False)
        if parent.returncode == 0 and parent.stdout.strip() == source_sha:
            return Version(current.major, current.minor, patch)
    return None


def next_version(root: pathlib.Path, current: Version, run_number: int, source_sha: str | None = None) -> Version:
    if run_number < 1:
        raise ValueError("run number must be positive")
    if source_sha:
        reused = version_already_released_from_source(root, current, source_sha)
        if reused is not None:
            return reused
    tag_patches = [patch for _, patch in matching_tags(root, current)]
    highest_tag = max(tag_patches, default=-1)
    patch = max(current.patch + 1, highest_tag + 1, run_number)
    return Version(current.major, current.minor, patch)


def generate_bootstrap_password() -> str:
    # 32 random bytes produce a 43-character URL-safe token. The character set
    # is accepted by nas-secrets' require_secret_atom validation.
    password = secrets.token_urlsafe(32)
    validate_bootstrap_password(password)
    return password


def validate_bootstrap_password(password: str) -> None:
    if not 20 <= len(password) <= 128 or SAFE_SECRET_RE.fullmatch(password) is None:
        raise ValueError("bootstrap password does not satisfy the NAS secret atom contract")


def discover_bootstrap_password(root: pathlib.Path) -> str:
    source = (root / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
    matches = BOOTSTRAP_RE.findall(source)
    if len(matches) != 1:
        raise RuntimeError("expected exactly one Authentik bootstrap-password seed in secret-tools.nix")
    password = matches[0]
    validate_bootstrap_password(password)
    application_services = (root / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
    if password not in application_services:
        raise RuntimeError("first-boot Authentik runtime does not use the same bootstrap password as nas-secrets")
    return password


def tracked_files_containing(root: pathlib.Path, needle: str) -> list[pathlib.Path]:
    result = run_git(root, "grep", "-l", "-F", "--", needle, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "git grep failed")
    return [root / line for line in result.stdout.splitlines() if line]


def rotate_bootstrap_password(root: pathlib.Path, old: str, new: str) -> list[str]:
    validate_bootstrap_password(new)
    if old == new:
        raise ValueError("new bootstrap password must differ from the previous release")
    paths = tracked_files_containing(root, old)
    relative_paths = {path.relative_to(root).as_posix() for path in paths}
    missing = sorted(CORE_BOOTSTRAP_PATHS - relative_paths)
    if missing:
        raise RuntimeError("bootstrap password is missing from required runtime paths: " + ", ".join(missing))
    changed: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        updated = text.replace(old, new)
        if updated == text:
            continue
        path.write_text(updated, encoding="utf-8")
        changed.append(path.relative_to(root).as_posix())
    return sorted(changed)


def replace_required(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise RuntimeError(f"{label} does not contain expected release metadata {old!r}")
    return text.replace(old, new)


def update_version_metadata(root: pathlib.Path, old: Version, new: Version, release_date: str) -> list[str]:
    old_text = str(old)
    new_text = str(new)
    changed = ["VERSION"]
    (root / "VERSION").write_text(new_text + "\n", encoding="utf-8")

    readme_path = root / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    readme = replace_required(readme, f"# NixOS NAS {old_text}", f"# NixOS NAS {new_text}", "README heading")
    readme = replace_required(
        readme,
        f"> **Release status:** {old_text}",
        f"> **Release status:** {new_text}",
        "README release status",
    )
    readme_path.write_text(readme, encoding="utf-8")
    changed.append("README.md")

    flake_path = root / "flake.nix"
    flake = flake_path.read_text(encoding="utf-8")
    description_old = f'description = "NixOS NAS {old_text} '
    description_new = f'description = "NixOS NAS {new_text} '
    flake_path.write_text(
        replace_required(flake, description_old, description_new, "flake description"), encoding="utf-8"
    )
    changed.append("flake.nix")

    package_path = root / "cockpit/package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    if package.get("version") != old_text:
        raise RuntimeError("cockpit/package.json version does not match VERSION")
    package["version"] = new_text
    package_path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    changed.append("cockpit/package.json")

    lock_path = root / "cockpit/package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    root_package = lock.get("packages", {}).get("")
    if lock.get("version") != old_text or not isinstance(root_package, dict) or root_package.get("version") != old_text:
        raise RuntimeError("cockpit/package-lock.json root versions do not match VERSION")
    lock["version"] = new_text
    root_package["version"] = new_text
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    changed.append("cockpit/package-lock.json")

    changelog_path = root / "CHANGELOG.md"
    changelog = changelog_path.read_text(encoding="utf-8")
    marker = f"## {old_text} "
    position = changelog.find(marker)
    if position < 0:
        raise RuntimeError("CHANGELOG.md does not contain the current VERSION release heading")
    section = (
        f"## {new_text} — {release_date}\n\n"
        "### Changed\n\n"
        "- Automated merge release: advanced the release version from "
        f"`{old_text}` to `{new_text}` and rotated the release-specific Authentik bootstrap credential.\n\n"
    )
    changelog_path.write_text(changelog[:position] + section + changelog[position:], encoding="utf-8")
    changed.append("CHANGELOG.md")
    return changed


def prepare_release(
    root: pathlib.Path,
    *,
    run_number: int,
    source_sha: str,
    metadata_out: pathlib.Path,
    password: str | None = None,
    release_date: str | None = None,
) -> dict[str, object]:
    root = root.resolve()
    current = Version.parse((root / "VERSION").read_text(encoding="utf-8"))
    target = next_version(root, current, run_number, source_sha)
    old_password = discover_bootstrap_password(root)
    new_password = password or generate_bootstrap_password()
    validate_bootstrap_password(new_password)

    date = release_date or dt.datetime.now(dt.UTC).date().isoformat()
    version_files = update_version_metadata(root, current, target, date)
    password_files = rotate_bootstrap_password(root, old_password, new_password)

    metadata: dict[str, object] = {
        "version": str(target),
        "previous_version": str(current),
        "tag": f"v{target}",
        "source_sha": source_sha,
        "bootstrap_username": BOOTSTRAP_USERNAME,
        "bootstrap_password": new_password,
        "version_files": sorted(version_files),
        "bootstrap_files": password_files,
    }
    metadata_out.parent.mkdir(parents=True, exist_ok=True)
    metadata_out.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stamp a merge checkout for an automated NixOS NAS release")
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--run-number", type=int, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--metadata-out", type=pathlib.Path, required=True)
    parser.add_argument("--password", help=argparse.SUPPRESS)
    parser.add_argument("--date", dest="release_date", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metadata = prepare_release(
        args.root,
        run_number=args.run_number,
        source_sha=args.source_sha,
        metadata_out=args.metadata_out,
        password=args.password,
        release_date=args.release_date,
    )
    # Deliberately do not print the password. It is published later in the
    # explicit GitHub Release notes, not leaked incidentally into workflow logs.
    print(f"prepared {metadata['tag']} from {metadata['source_sha']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
