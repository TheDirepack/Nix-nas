"""Prepare one release commit from a qualified main-branch source commit.

The GitHub release workflow invokes this module with ``python3``. It keeps the
release-specific mutations in one tested place: deterministic version stamping,
bootstrap-password rotation, and synchronized release metadata.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
from dataclasses import dataclass

VERSION_RE = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)$")
BOOTSTRAP_RE = re.compile(r'store_value authentik-bootstrap-password "([^"\n]+)"')
AUTHENTIK_ENV_RE = re.compile(r"AUTHENTIK_BOOTSTRAP_PASSWORD=([A-Za-z0-9._~+/=:@-]+)")
SAFE_SECRET_RE = re.compile(r"^[A-Za-z0-9._~+/=:@-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BOOTSTRAP_USERNAME = "akadmin"
RELEASE_EPOCH_PATH = pathlib.Path(".github/release-version-epoch.json")
BOOTSTRAP_TARGETS = {
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


def release_tag_for_source(root: pathlib.Path, current: Version, source_sha: str) -> tuple[str, Version] | None:
    for tag, patch in sorted(matching_tags(root, current), key=lambda item: item[1], reverse=True):
        parent = run_git(root, "rev-parse", f"{tag}^{{commit}}^1", check=False)
        if parent.returncode == 0 and parent.stdout.strip() == source_sha:
            return tag, Version(current.major, current.minor, patch)
    return None


def is_ancestor(root: pathlib.Path, older: str, newer: str) -> bool:
    result = run_git(root, "merge-base", "--is-ancestor", older, newer, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "git merge-base failed")
    return result.returncode == 0


def release_epoch(root: pathlib.Path) -> tuple[Version, str]:
    path = root / RELEASE_EPOCH_PATH
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{RELEASE_EPOCH_PATH} must contain a JSON object")
    version = Version.parse(str(raw.get("version", "")))
    source_sha = str(raw.get("sourceSha", ""))
    if SHA_RE.fullmatch(source_sha) is None:
        raise RuntimeError(f"{RELEASE_EPOCH_PATH} contains an invalid sourceSha")
    return version, source_sha


def version_anchor(root: pathlib.Path, current: Version, source_sha: str) -> str:
    version_commit = run_git(root, "log", "-1", "--format=%H", source_sha, "--", "VERSION").stdout.strip()
    if SHA_RE.fullmatch(version_commit) is None:
        raise RuntimeError("could not resolve the commit that established VERSION")

    epoch_version, epoch_source = release_epoch(root)
    if (
        current == epoch_version
        and is_ancestor(root, version_commit, epoch_source)
        and is_ancestor(root, epoch_source, source_sha)
    ):
        return epoch_source

    if not is_ancestor(root, version_commit, source_sha):
        raise RuntimeError("VERSION anchor is not an ancestor of the release source")
    return version_commit


def next_version(root: pathlib.Path, current: Version, source_sha: str) -> Version:
    """Map a main source commit to a deterministic patch version.

    The first-parent distance from the version anchor gives every qualified main
    source a unique version without requiring workflow-level serialization.
    Existing tags remain authoritative for publication retries.
    """
    existing = release_tag_for_source(root, current, source_sha)
    if existing is not None:
        return existing[1]

    anchor = version_anchor(root, current, source_sha)
    result = run_git(
        root,
        "rev-list",
        "--count",
        "--first-parent",
        f"{anchor}..{source_sha}",
    )
    try:
        distance = int(result.stdout.strip())
    except ValueError as exc:
        raise RuntimeError("git returned an invalid first-parent release distance") from exc
    if distance < 0:
        raise RuntimeError("release distance cannot be negative")
    return Version(current.major, current.minor, current.patch + distance)


def validate_bootstrap_password(password: str) -> None:
    if not 20 <= len(password) <= 128 or SAFE_SECRET_RE.fullmatch(password) is None:
        raise ValueError("bootstrap password does not satisfy the NAS secret atom contract")


def validate_release_passphrase(password: str) -> None:
    validate_bootstrap_password(password)
    words = password.split("-")
    if len(words) != 5 or any(not word or not word.isalpha() or not word.isascii() for word in words):
        raise ValueError("release bootstrap password must be exactly five hyphen-separated words")


def bootstrap_password_from_text(source: str, label: str) -> str:
    matches = BOOTSTRAP_RE.findall(source)
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one Authentik bootstrap-password seed in {label}")
    password = matches[0]
    validate_bootstrap_password(password)
    return password


def application_bootstrap_password_from_text(source: str, label: str) -> str:
    matches = AUTHENTIK_ENV_RE.findall(source)
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one AUTHENTIK_BOOTSTRAP_PASSWORD assignment in {label}")
    password = matches[0]
    validate_bootstrap_password(password)
    return password


def discover_bootstrap_password(root: pathlib.Path) -> str:
    secret_tools = (root / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
    password = bootstrap_password_from_text(secret_tools, "secret-tools.nix")
    application_services = (root / "modules/nas/config/application-services.nix").read_text(encoding="utf-8")
    runtime_password = application_bootstrap_password_from_text(application_services, "application-services.nix")
    if password != runtime_password:
        raise RuntimeError("first-boot Authentik runtime does not use the same bootstrap password as nas-secrets")
    return password


def bootstrap_password_from_tag(root: pathlib.Path, tag: str) -> str:
    result = run_git(root, "show", f"{tag}:modules/nas/internal/secret-tools.nix")
    return bootstrap_password_from_text(result.stdout, f"{tag}:secret-tools.nix")


def tracked_files_containing(root: pathlib.Path, needle: str) -> list[pathlib.Path]:
    result = run_git(root, "grep", "-l", "-F", "--", needle, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "git grep failed")
    return [root / line for line in result.stdout.splitlines() if line]


def rotate_bootstrap_password(root: pathlib.Path, old: str, new: str) -> list[str]:
    validate_release_passphrase(new)
    if old == new:
        raise ValueError("new bootstrap password must differ from the development bootstrap password")

    changed: list[str] = []
    for relative in sorted(BOOTSTRAP_TARGETS):
        path = root / relative
        text = path.read_text(encoding="utf-8")
        occurrences = text.count(old)
        if occurrences != 1:
            raise RuntimeError(
                f"{relative} must contain the development bootstrap password exactly once; found {occurrences}"
            )
        updated = text.replace(old, new, 1)
        path.write_text(updated, encoding="utf-8")
        changed.append(relative)

    return changed


def replace_required(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise RuntimeError(f"{label} does not contain expected release metadata {old!r}")
    return text.replace(old, new)


def prior_published_changelog_sections(root: pathlib.Path, current: Version, target: Version) -> str:
    prior = [(tag, patch) for tag, patch in matching_tags(root, target) if current.patch < patch < target.patch]
    if not prior:
        return ""
    tag, _ = max(prior, key=lambda item: item[1])
    changelog = run_git(root, "show", f"{tag}:CHANGELOG.md").stdout
    first_release = re.search(r"(?m)^## ", changelog)
    current_heading = re.search(rf"(?m)^## {re.escape(str(current))} [^\n]*$", changelog)
    if first_release is None or current_heading is None:
        raise RuntimeError(f"{tag}:CHANGELOG.md does not preserve the {current} baseline heading")
    if first_release.start() >= current_heading.start():
        return ""
    return changelog[first_release.start() : current_heading.start()]


def update_version_metadata(
    root: pathlib.Path,
    old: Version,
    new: Version,
    release_date: str,
    prior_sections: str = "",
) -> list[str]:
    old_text = str(old)
    new_text = str(new)
    changed = ["VERSION"]
    (root / "VERSION").write_text(new_text + "\n", encoding="utf-8")

    readme_path = root / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    readme = replace_required(
        readme,
        f"# NixOS NAS {old_text}",
        f"# NixOS NAS {new_text}",
        "README heading",
    )
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
        replace_required(flake, description_old, description_new, "flake description"),
        encoding="utf-8",
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
        f"`{old_text}` to `{new_text}` and rotated the release-only Authentik "
        "bootstrap credential.\n\n"
    )
    changelog_path.write_text(
        changelog[:position] + section + prior_sections + changelog[position:],
        encoding="utf-8",
    )
    changed.append("CHANGELOG.md")
    return changed


def prepare_release(
    root: pathlib.Path,
    *,
    source_sha: str,
    metadata_out: pathlib.Path,
    password: str | None = None,
    release_date: str | None = None,
) -> dict[str, object]:
    root = root.resolve()
    current = Version.parse((root / "VERSION").read_text(encoding="utf-8"))
    existing = release_tag_for_source(root, current, source_sha)
    target = existing[1] if existing is not None else next_version(root, current, source_sha)
    development_password = discover_bootstrap_password(root)

    if existing is not None:
        release_password = bootstrap_password_from_tag(root, existing[0])
    elif password is not None:
        release_password = password
    else:
        raise ValueError("new releases require a Diceware bootstrap password supplied by the release workflow")
    validate_release_passphrase(release_password)

    date = release_date or dt.datetime.now(dt.UTC).date().isoformat()
    prior_sections = prior_published_changelog_sections(root, current, target)
    version_files = update_version_metadata(root, current, target, date, prior_sections=prior_sections)
    password_files = rotate_bootstrap_password(root, development_password, release_password)

    metadata: dict[str, object] = {
        "version": str(target),
        "previous_version": str(current),
        "tag": f"v{target}",
        "existing_tag": existing[0] if existing is not None else "",
        "source_sha": source_sha,
        "bootstrap_username": BOOTSTRAP_USERNAME,
        "bootstrap_password": release_password,
        "version_files": sorted(version_files),
        "bootstrap_files": password_files,
    }
    metadata_out.parent.mkdir(parents=True, exist_ok=True)
    metadata_out.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Stamp a qualified main source commit for an automated NixOS NAS release"
    )
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--metadata-out", type=pathlib.Path, required=True)
    parser.add_argument("--password", help=argparse.SUPPRESS)
    parser.add_argument("--date", dest="release_date", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metadata = prepare_release(
        args.root,
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
