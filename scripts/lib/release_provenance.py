"""Generate deterministic release provenance metadata from an explicitly staged tree."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
from collections.abc import Sequence


def optional_hash(stage: pathlib.Path, relative: str) -> str | None:
    candidate = stage / relative
    if not candidate.is_file():
        return None
    return hashlib.sha256(candidate.read_bytes()).hexdigest()


def version_of(command: Sequence[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    lines = result.stdout.strip().splitlines()
    return lines[0] if lines else "unavailable"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="release-provenance")
    result.add_argument("--out", required=True)
    result.add_argument("--version", required=True)
    result.add_argument("--artifact-name", required=True)
    result.add_argument("--archive-root", required=True)
    result.add_argument("--validation", choices=("source-only", "complete"), required=True)
    result.add_argument("--archive-hash", required=True)
    result.add_argument("--manifest-hash", required=True)
    result.add_argument("--flake-hash", required=True)
    result.add_argument("--commit", required=True)
    result.add_argument("--selection-policy", required=True)
    result.add_argument("--status", required=True)
    result.add_argument("--stage-root", required=True)
    result.add_argument("--git-tree", default="unavailable")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    stage = pathlib.Path(args.stage_root).resolve(strict=True)
    status_path = pathlib.Path(args.status)
    status = json.loads(status_path.read_text(encoding="utf-8"))
    payload = {
        "archive": f"{args.artifact_name}.zip",
        "archiveRoot": args.archive_root,
        "artifactName": args.artifact_name,
        "archiveSha256": args.archive_hash,
        "builderIdentity": os.environ.get("GITHUB_ACTOR") or os.environ.get("USER") or "unknown",
        "builderPlatform": platform.platform(),
        "buildTimestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "buildRun": {
            "provider": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local",
            "runId": os.environ.get("GITHUB_RUN_ID"),
            "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
        },
        "cockpitBuildMetaSha256": optional_hash(stage, "cockpit/dist/build-meta.json"),
        "cockpitPackageLockSha256": optional_hash(stage, "cockpit/package-lock.json"),
        "evidence": {
            "qemuCommitSha256": optional_hash(stage, "release-evidence/qemu/commit.txt"),
            "qemuChecksSha256": optional_hash(stage, "release-evidence/qemu/checks.txt"),
            "installerCommitSha256": optional_hash(stage, "release-evidence/installer/commit.txt"),
            "installerChecksSha256": optional_hash(stage, "release-evidence/installer/checks.txt"),
        },
        "fileSelectionPolicy": args.selection_policy,
        "flakeLockSha256": args.flake_hash,
        "gitCommit": args.commit,
        "gitTree": args.git_tree,
        "manifest": f"{args.artifact_name}.MANIFEST.sha256",
        "manifestSha256": args.manifest_hash,
        "preflight": status,
        "sourceOnly": args.validation == "source-only",
        "toolVersions": {
            "python": sys.version.split()[0],
            "nix": version_of(["nix", "--version"]),
            "node": version_of(["node", "--version"]),
            "ruff": version_of(["ruff", "--version"]),
            "pyright": version_of(["pyright", "--version"]),
            "shellcheck": version_of(["shellcheck", "--version"]),
            "minisign": version_of(["minisign", "-v"]),
        },
        "validationMode": args.validation,
        "version": args.version,
    }
    pathlib.Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
