#!/usr/bin/env python3
"""Interpret the configured Restic recovery backup for status and readiness.

Nix owns the backup configuration and writes a non-secret policy file. This
command classifies where the configured repository lives, reports the last
recorded backup and restore-verification results, and never prints the
repository string itself: a Restic repository URL may embed credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable

from nas_common import fsync_directory

DEFAULT_POLICY_PATH = pathlib.Path(os.environ.get("NAS_BACKUP_POLICY", "/etc/nas-control/backup-policy.json"))
DEFAULT_MOUNTINFO_PATH = pathlib.Path(os.environ.get("NAS_BACKUP_MOUNTINFO", "/proc/self/mountinfo"))
RECORD_NAMES = ("backup", "restore-verify")
MAX_REPOSITORY_BYTES = 4096
NETWORK_BACKENDS = frozenset({"sftp", "rest", "s3", "azure", "gs", "swift", "b2", "rclone"})
# Memory-backed and kernel pseudo filesystems lose a repository at reboot.
VOLATILE_FILESYSTEMS = frozenset(
    {
        "tmpfs",
        "ramfs",
        "devtmpfs",
        "proc",
        "sysfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "debugfs",
        "tracefs",
        "securityfs",
        "configfs",
        "pstore",
        "bpf",
        "efivarfs",
        "mqueue",
        "hugetlbfs",
    }
)
_SCHEME = re.compile(r"^([a-z][a-z0-9]*):")


class BackupStatusError(RuntimeError):
    """Raised when the backup policy or a repository reference is unusable."""


def load_policy(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupStatusError(f"Backup policy is unavailable: {path}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise BackupStatusError(f"Backup policy has an unsupported shape: {path}")
    for key in ("enabled", "allowSamePoolRepository", "replication", "restoreVerification"):
        if not isinstance(value.get(key), bool):
            raise BackupStatusError(f"Backup policy field {key} must be a boolean")
    if value.get("repositorySource") not in {"local", "repository-file"}:
        raise BackupStatusError("Backup policy repositorySource must be local or repository-file")
    for key in ("zfsPool", "zfsRoot", "localRepository", "recordDirectory"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise BackupStatusError(f"Backup policy field {key} must be a non-empty string")
    for key in ("zfsRoot", "localRepository", "recordDirectory"):
        if not value[key].startswith("/"):
            raise BackupStatusError(f"Backup policy field {key} must be absolute")
    if value["repositorySource"] == "repository-file":
        repository_file = value.get("repositoryFile")
        if not isinstance(repository_file, str) or not repository_file.startswith("/"):
            raise BackupStatusError("Backup policy repositoryFile must be an absolute path")
    return value


def read_repository_reference(path: pathlib.Path) -> str:
    """Read the repository string the way Restic's --repository-file does."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_REPOSITORY_BYTES + 1)
    except OSError as exc:
        raise BackupStatusError("The Restic repository file is unreadable") from exc
    if len(raw) > MAX_REPOSITORY_BYTES:
        raise BackupStatusError("The Restic repository file is too large")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise BackupStatusError("The Restic repository file is not UTF-8 text") from exc
    if not value or "\n" in value or "\r" in value:
        raise BackupStatusError("The Restic repository file must contain exactly one repository")
    return value


def _unescape_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def parse_mountinfo(text: str) -> list[tuple[str, str, str]]:
    """Return (mount point, filesystem type, source) for each mountinfo row."""
    mounts: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        left, separator, right = line.partition(" - ")
        fields = left.split()
        tail = right.split()
        if not separator or len(fields) < 5 or len(tail) < 2:
            continue
        mounts.append((_unescape_mount_field(fields[4]), tail[0], _unescape_mount_field(tail[1])))
    return mounts


def _under(path: pathlib.PurePosixPath, root: pathlib.PurePosixPath) -> bool:
    return path == root or root in path.parents


def _containing_mount(path: pathlib.PurePosixPath, mounts: list[tuple[str, str, str]]) -> tuple[str, str, str] | None:
    best: tuple[str, str, str] | None = None
    for mount in mounts:
        if _under(path, pathlib.PurePosixPath(mount[0])) and (best is None or len(mount[0]) >= len(best[0])):
            best = mount
    return best


def _on_pool(source: str, pool: str) -> bool:
    return source == pool or source.startswith(pool + "/")


def classify_repository(
    reference: str,
    *,
    zfs_pool: str,
    zfs_root: str,
    mountinfo: str | None,
    realpath: Callable[[str], str] = os.path.realpath,
) -> dict[str, str]:
    """Classify a Restic repository string without returning the string.

    ``location`` is ``network`` for a Restic network backend, ``same-pool`` for
    a local path on the managed pool, ``system-disk`` for a path on the root
    filesystem, ``volatile`` for a memory-backed or pseudo filesystem,
    ``off-pool`` for a local path mounted from another filesystem,
    ``unverified`` when the mount cannot be determined, and ``invalid`` for a
    relative path, an unknown scheme, or a backend without a destination.
    """
    match = _SCHEME.match(reference)
    scheme = match.group(1) if match else None
    if scheme in NETWORK_BACKENDS:
        if not reference[len(scheme) + 1 :].strip(":/ \t"):
            return {"backend": scheme, "location": "invalid"}
        return {"backend": scheme, "location": "network"}
    if scheme == "local":
        candidate = reference[len("local:") :]
    elif reference.startswith("/"):
        candidate = reference
    else:
        return {"backend": scheme or "local", "location": "invalid"}
    if not candidate.startswith("/"):
        return {"backend": "local", "location": "invalid"}
    root = pathlib.PurePosixPath(os.path.normpath(zfs_root))
    lexical = pathlib.PurePosixPath(os.path.normpath(candidate))
    resolved = pathlib.PurePosixPath(realpath(candidate))
    if _under(lexical, root) or _under(resolved, root):
        return {"backend": "local", "location": "same-pool"}
    if mountinfo is None:
        return {"backend": "local", "location": "unverified"}
    mount = _containing_mount(resolved, parse_mountinfo(mountinfo))
    if mount is None:
        return {"backend": "local", "location": "unverified"}
    if mount[1] == "zfs" and _on_pool(mount[2], zfs_pool):
        return {"backend": "local", "location": "same-pool"}
    if mount[1] in VOLATILE_FILESYSTEMS:
        return {"backend": "local", "location": "volatile"}
    if mount[0] == "/":
        return {"backend": "local", "location": "system-disk"}
    return {"backend": "local", "location": "off-pool"}


def _read_optional_text(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _repository_reference(policy: dict[str, Any]) -> tuple[str, str]:
    if policy["repositorySource"] == "repository-file":
        return "repository-file", read_repository_reference(pathlib.Path(policy["repositoryFile"]))
    return "local", policy["localRepository"]


def _fingerprint(source: str, reference: str) -> str:
    # Identifies the destination a run used without storing the secret string.
    return hashlib.sha256(f"nas-backup-repository\0{source}\0{reference}".encode()).hexdigest()


def repository_fingerprint(policy: dict[str, Any]) -> str | None:
    try:
        return _fingerprint(*_repository_reference(policy))
    except BackupStatusError:
        return None


def configured_repository(policy: dict[str, Any], *, mountinfo: str | None) -> dict[str, str]:
    """Classify the repository the Restic units use under ``policy``."""
    try:
        source, reference = _repository_reference(policy)
    except BackupStatusError as exc:
        return {"source": "repository-file", "backend": "unknown", "location": "unavailable", "error": str(exc)}
    classified = classify_repository(
        reference,
        zfs_pool=policy["zfsPool"],
        zfs_root=policy["zfsRoot"],
        mountinfo=mountinfo,
    )
    return {"source": source, **classified}


def _record_path(policy: dict[str, Any], name: str) -> pathlib.Path:
    if name not in RECORD_NAMES:
        raise BackupStatusError(f"Unknown backup record: {name}")
    return pathlib.Path(policy["recordDirectory"]) / f"{name}.json"


def read_record(policy: dict[str, Any], name: str) -> dict[str, Any] | None:
    text = _read_optional_text(_record_path(policy, name))
    if text is None:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("result"), str):
        return None
    if not isinstance(value.get("finishedAt"), str):
        return None
    return value


def write_record(
    policy: dict[str, Any],
    name: str,
    environment: dict[str, str],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Persist systemd's ExecStopPost result for one backup unit run."""
    result = environment.get("SERVICE_RESULT", "")
    if not re.fullmatch(r"[a-z][a-z-]{0,63}", result):
        raise BackupStatusError("SERVICE_RESULT is missing; run this from ExecStopPost")
    record = {
        "result": result,
        "exitCode": environment.get("EXIT_CODE", "")[:64],
        "exitStatus": environment.get("EXIT_STATUS", "")[:64],
        "finishedAt": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "repository": repository_fingerprint(policy),
    }
    path = _record_path(policy, name)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(record, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)
    return record


def _row(row_id: str, label: str, state: str, summary: str, detail: str) -> dict[str, str]:
    return {"id": row_id, "label": label, "state": state, "summary": summary, "detail": detail}


_LOCATION_TEXT = {
    "network": ("ok", "Off-pool", "Network {backend} repository named by nas.backup.repositoryFile."),
    "off-pool": ("ok", "Off-pool", "Local repository on a filesystem outside the managed pool."),
    "same-pool": (
        "attention",
        "Same pool",
        "The repository is on the managed ZFS pool. It is rollback storage, not an independent backup.",
    ),
    "system-disk": (
        "attention",
        "System disk",
        "The repository is on the root filesystem. It survives pool loss but not boot-device loss; "
        "check that its intended disk is mounted.",
    ),
    "volatile": (
        "attention",
        "Volatile",
        "The repository is on a memory-backed or pseudo filesystem and is lost at reboot.",
    ),
    "unverified": (
        "attention",
        "Unverified",
        "The repository is a local path whose filesystem could not be determined.",
    ),
    "invalid": (
        "attention",
        "Invalid",
        "The repository is a relative path, an unknown Restic backend, or a backend without a destination.",
    ),
    "unavailable": ("unavailable", "Unavailable", "{error}"),
}


def _current_record(policy: dict[str, Any], name: str, fingerprint: str | None) -> dict[str, Any] | None:
    """Return the record only when it was written for the current repository."""
    record = read_record(policy, name)
    if record is None or fingerprint is None or record.get("repository") != fingerprint:
        return None
    return record


def _finished(record: dict[str, Any]) -> datetime | None:
    try:
        value = datetime.fromisoformat(record["finishedAt"])
    except ValueError:
        return None
    return value if value.tzinfo is not None else None


def _run_row(
    row_id: str, label: str, record: dict[str, Any] | None, success_text: str, *, caveat: str = ""
) -> dict[str, str]:
    if record is None:
        return _row(
            row_id,
            label,
            "unavailable",
            "No run recorded",
            "No completed run has been recorded for the current repository.",
        )
    finished = record["finishedAt"]
    if record["result"] == "success":
        return _row(row_id, label, "ok", "Succeeded", f"{success_text} {finished}.{caveat}")
    return _row(
        row_id,
        label,
        "attention",
        "Failed",
        f"The last run ended with result {record['result']} at {finished}. Inspect the unit journal.",
    )


def backup_status(policy: dict[str, Any], *, mountinfo: str | None) -> dict[str, Any]:
    """Return separate configured, completed and restore-verified observations."""
    rows: list[dict[str, str]] = []
    repository: dict[str, str] | None = None
    if policy["enabled"]:
        repository = configured_repository(policy, mountinfo=mountinfo)
        state, summary, detail = _LOCATION_TEXT[repository["location"]]
        rows.append(
            _row(
                "repository",
                "Restic repository",
                state,
                summary,
                detail.format(backend=repository["backend"], error=repository.get("error", "")),
            )
        )
    else:
        rows.append(
            _row(
                "repository",
                "Restic repository",
                "attention",
                "Not configured",
                "Restic recovery backup is disabled (nas.backup.enable = false).",
            )
        )
    restic_independent = repository is not None and repository["location"] in {"network", "off-pool"}
    independent = restic_independent or policy["replication"]
    if policy["replication"]:
        rows.append(
            _row(
                "replication",
                "ZFS replication",
                "ok",
                "Configured",
                "nas.zfsReplication copies the managed dataset to another ZFS target.",
            )
        )
    fingerprint = repository_fingerprint(policy) if policy["enabled"] else None
    last_backup = _current_record(policy, "backup", fingerprint) if policy["enabled"] else None
    if policy["enabled"]:
        rows.append(_run_row("last-backup", "Last backup", last_backup, "The last backup completed at"))
    last_verify = _current_record(policy, "restore-verify", fingerprint) if policy["restoreVerification"] else None
    if policy["restoreVerification"]:
        caveat = ""
        if last_verify is not None and last_backup is not None and last_backup["result"] == "success":
            backup_time, verify_time = _finished(last_backup), _finished(last_verify)
            if backup_time is not None and verify_time is not None and backup_time > verify_time:
                caveat = " Snapshots from later backups have not been restore-verified yet."
        rows.append(
            _run_row(
                "restore-verification",
                "Restore verification",
                last_verify,
                "The snapshot that was latest when verification started was restored and validated in "
                "scratch storage on this host; verification finished at",
                caveat=caveat,
            )
        )
    elif policy["enabled"]:
        rows.append(
            _row(
                "restore-verification",
                "Restore verification",
                "attention",
                "Disabled",
                "Scheduled restore verification is disabled (nas.backup.restoreVerification.enable = false).",
            )
        )
    rows.append(
        _row(
            "independent-restore",
            "Independent restore",
            "unavailable",
            "Not proven",
            "The appliance cannot prove disaster recovery. Run the boot-device replacement drill with "
            "independently stored KeePass material.",
        )
    )
    return {
        "ok": bool(independent and last_backup is not None and last_backup["result"] == "success"),
        "enabled": policy["enabled"],
        "independentCopyConfigured": independent,
        "repository": repository,
        "lastBackup": last_backup,
        "lastRestoreVerification": last_verify,
        "independentRestoreProven": False,
        "rows": rows,
    }


def check_readiness(policy: dict[str, Any], *, mountinfo: str | None) -> list[str]:
    """Return reasons the configuration cannot claim an off-pool copy.

    ZFS replication satisfies the requirement on its own. Otherwise the Restic
    repository must be readable and must not name a path on the managed pool.
    A path that currently resolves to the root filesystem is not rejected here:
    at boot its intended disk may not be mounted yet, so status reports it.
    Every other location that is not demonstrably off-pool fails closed.
    """
    if policy["replication"]:
        return []
    if not policy["enabled"] or policy["repositorySource"] != "repository-file":
        return ["installationReady requires an off-pool Restic repository or enabled ZFS replication."]
    repository = configured_repository(policy, mountinfo=mountinfo)
    location = repository["location"]
    if location == "unavailable":
        return [repository["error"]]
    if location == "same-pool":
        return ["nas.backup.repositoryFile names a path on the managed ZFS pool; it is not an independent backup."]
    if location == "invalid":
        return [
            "nas.backup.repositoryFile must name an absolute local path or a supported Restic backend with a destination."
        ]
    if location == "volatile":
        return ["nas.backup.repositoryFile names a memory-backed or pseudo filesystem that is lost at reboot."]
    if location == "unverified":
        return ["nas.backup.repositoryFile names a local path whose filesystem could not be determined."]
    return []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=pathlib.Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--mountinfo", type=pathlib.Path, default=DEFAULT_MOUNTINFO_PATH)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Print backup status as JSON")
    commands.add_parser("check-readiness", help="Fail unless an off-pool copy is configured")
    record = commands.add_parser("record", help="Record a backup unit result from ExecStopPost")
    record.add_argument("name", choices=RECORD_NAMES)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
        if args.command == "record":
            write_record(policy, args.name, dict(os.environ))
            return 0
        mountinfo = _read_optional_text(args.mountinfo)
        if args.command == "check-readiness":
            failures = check_readiness(policy, mountinfo=mountinfo)
            for failure in failures:
                print(failure, file=sys.stderr)
            return 1 if failures else 0
        print(json.dumps(backup_status(policy, mountinfo=mountinfo), indent=2, sort_keys=True))
        return 0
    except BackupStatusError as exc:
        print(f"nas-backup-status: {exc}", file=sys.stderr)
        return 2


def status_from_environment() -> dict[str, Any]:
    """Status for the Cockpit overview, with an explicit unavailable result."""
    try:
        policy = load_policy(DEFAULT_POLICY_PATH)
    except BackupStatusError as exc:
        return {"ok": False, "error": str(exc), "rows": []}
    return backup_status(policy, mountinfo=_read_optional_text(DEFAULT_MOUNTINFO_PATH))


if __name__ == "__main__":
    raise SystemExit(main())
