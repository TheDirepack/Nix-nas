from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_backup_status as status  # noqa: E402

MOUNTINFO = "\n".join(
    [
        "22 1 0:21 / / rw,relatime shared:1 - ext4 /dev/sda2 rw",
        "40 22 0:40 / /tank rw shared:20 - zfs tank/nas rw,xattr",
        "41 22 0:41 / /srv/apps rw shared:21 - zfs tank/apps rw,xattr",
        "42 22 0:42 / /mnt/usb\\040disk rw shared:22 - ext4 /dev/sdb1 rw",
        "43 22 0:43 / /backup rw shared:23 - zfs vault/restic rw,xattr",
        "44 22 0:44 / /tankfoo rw shared:24 - xfs /dev/sdc1 rw",
        "45 22 0:45 / /run rw shared:25 - tmpfs tmpfs rw",
        "46 22 0:46 / /dev/shm rw shared:26 - tmpfs tmpfs rw",
        "47 22 0:47 / /proc rw shared:27 - proc proc rw",
        "malformed row without separator",
    ]
)
SECRET_REPOSITORY = "rest:https://backup-user:hunter2-secret@backup.example.test/nas"


def classify(reference: str, *, mountinfo: str | None = MOUNTINFO, realpath=lambda value: value) -> str:
    return status.classify_repository(
        reference, zfs_pool="tank", zfs_root="/tank", mountinfo=mountinfo, realpath=realpath
    )["location"]


class RepositoryClassificationTests(unittest.TestCase):
    def test_network_backends_are_off_pool_and_named_only_by_backend(self) -> None:
        for reference, backend in (
            ("rclone:gdrive:nas-backup", "rclone"),
            ("s3:s3.amazonaws.com/bucket/nas", "s3"),
            ("b2:bucket:nas", "b2"),
            ("sftp:backup@host:/srv/restic", "sftp"),
            (SECRET_REPOSITORY, "rest"),
            ("azure:container:/nas", "azure"),
            ("gs:bucket:/nas", "gs"),
            ("swift:container:/nas", "swift"),
        ):
            with self.subTest(reference=reference):
                result = status.classify_repository(reference, zfs_pool="tank", zfs_root="/tank", mountinfo=None)
                self.assertEqual(result, {"backend": backend, "location": "network"})

    def test_paths_on_the_managed_pool_are_same_pool(self) -> None:
        for reference in (
            "/tank/backups/restic-system",
            "local:/tank/backups/restic-system",
            "/tank",
            "/tank/../tank/backups",
            "/srv/apps/restic",
        ):
            with self.subTest(reference=reference):
                self.assertEqual(classify(reference), "same-pool")
        # Lexical containment is decisive even before the pool is mounted.
        self.assertEqual(classify("/tank/backups", mountinfo=None), "same-pool")

    def test_symlink_into_the_pool_is_same_pool(self) -> None:
        self.assertEqual(
            classify("/var/backups/restic", realpath=lambda value: "/tank/backups/restic"),
            "same-pool",
        )

    def test_other_filesystems_and_other_pools_are_off_pool(self) -> None:
        for reference in ("/mnt/usb disk/restic", "/backup/restic", "/tankfoo/restic"):
            with self.subTest(reference=reference):
                self.assertEqual(classify(reference), "off-pool")
        # An unmounted backup disk resolves to the root filesystem, which does
        # not survive boot-device loss.
        self.assertEqual(classify("/var/lib/restic"), "system-disk")
        self.assertEqual(classify("/mnt/usb/restic"), "system-disk")

    def test_unknown_mount_is_unverified_and_malformed_repositories_are_invalid(self) -> None:
        self.assertEqual(classify("/mnt/usb/restic", mountinfo=None), "unverified")
        self.assertEqual(classify("/mnt/usb/restic", mountinfo="garbage"), "unverified")
        for reference in ("backups/restic", "local:relative", "ftp:host/path", "C:\\restic"):
            with self.subTest(reference=reference):
                self.assertEqual(classify(reference), "invalid")

    def test_backend_without_a_destination_is_invalid(self) -> None:
        for reference in ("rclone:", "s3:", "rest:/", "sftp: ", "b2:::"):
            with self.subTest(reference=reference):
                self.assertEqual(classify(reference), "invalid")

    def test_memory_backed_and_pseudo_filesystems_are_volatile(self) -> None:
        for reference in ("/run/restic", "local:/dev/shm/restic", "/proc/restic"):
            with self.subTest(reference=reference):
                self.assertEqual(classify(reference), "volatile")


class PolicyFixture:
    def __init__(self, root: pathlib.Path, **overrides) -> None:
        self.root = root
        self.repository_file = root / "restic-repository"
        self.mountinfo = root / "mountinfo"
        self.mountinfo.write_text(MOUNTINFO, encoding="utf-8")
        self.policy = {
            "schemaVersion": 1,
            "enabled": True,
            "repositorySource": "repository-file",
            "localRepository": "/tank/backups/restic-system",
            "repositoryFile": str(self.repository_file),
            "allowSamePoolRepository": False,
            "replication": False,
            "restoreVerification": True,
            "zfsPool": "tank",
            "zfsRoot": "/tank",
            "recordDirectory": str(root / "records"),
        }
        self.policy.update(overrides)
        self.path = root / "backup-policy.json"
        self.path.write_text(json.dumps(self.policy), encoding="utf-8")

    def repository(self, value: str) -> None:
        self.repository_file.write_text(value, encoding="utf-8")
        self.repository_file.chmod(0o600)

    def main(self, *argv: str, env: dict[str, str] | None = None) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            mock.patch.dict(os.environ, env or {}, clear=False),
        ):
            code = status.main(["--policy", str(self.path), "--mountinfo", str(self.mountinfo), *argv])
        return code, stdout.getvalue(), stderr.getvalue()


class BackupStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def rows(self, value: dict) -> dict[str, dict[str, str]]:
        return {row["id"]: row for row in value["rows"]}

    def test_configured_completed_and_restore_verified_are_distinct_observations(self) -> None:
        fixture = PolicyFixture(self.root)
        fixture.repository("rclone:gdrive:nas-backup\n")

        code, out, _ = fixture.main("status")
        self.assertEqual(code, 0)
        value = json.loads(out)
        rows = self.rows(value)
        self.assertEqual(rows["repository"]["state"], "ok")
        self.assertTrue(value["independentCopyConfigured"])
        self.assertFalse(value["ok"], "a configured repository is not a completed backup")
        self.assertEqual(rows["last-backup"]["state"], "unavailable")
        self.assertEqual(rows["restore-verification"]["state"], "unavailable")
        self.assertEqual(rows["independent-restore"]["summary"], "Not proven")
        self.assertFalse(value["independentRestoreProven"])

        finished = {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}
        self.assertEqual(fixture.main("record", "backup", env=finished)[0], 0)
        value = json.loads(fixture.main("status")[1])
        rows = self.rows(value)
        self.assertTrue(value["ok"])
        self.assertEqual(rows["last-backup"]["state"], "ok")
        self.assertEqual(rows["restore-verification"]["state"], "unavailable")
        self.assertFalse(value["independentRestoreProven"])

        self.assertEqual(fixture.main("record", "restore-verify", env=finished)[0], 0)
        value = json.loads(fixture.main("status")[1])
        rows = self.rows(value)
        self.assertEqual(rows["restore-verification"]["state"], "ok")
        self.assertIn("on this host", rows["restore-verification"]["detail"])
        # Restoring on the same host never proves disaster recovery.
        self.assertFalse(value["independentRestoreProven"])
        self.assertNotEqual(rows["independent-restore"]["state"], "ok")

    def test_success_for_a_previous_repository_is_not_reported_for_the_current_one(self) -> None:
        fixture = PolicyFixture(self.root)
        fixture.repository("rclone:old:nas-backup")
        finished = {"SERVICE_RESULT": "success"}
        self.assertEqual(fixture.main("record", "backup", env=finished)[0], 0)
        self.assertEqual(fixture.main("record", "restore-verify", env=finished)[0], 0)
        self.assertTrue(json.loads(fixture.main("status")[1])["ok"])
        record = json.loads((self.root / "records" / "backup.json").read_text(encoding="utf-8"))
        self.assertNotIn("old:nas-backup", json.dumps(record))

        fixture.repository("rclone:new:nas-backup")
        value = json.loads(fixture.main("status")[1])
        rows = self.rows(value)
        self.assertFalse(value["ok"])
        self.assertIsNone(value["lastBackup"])
        self.assertEqual(rows["last-backup"]["summary"], "No run recorded")
        self.assertIn("current repository", rows["last-backup"]["detail"])
        self.assertEqual(rows["restore-verification"]["summary"], "No run recorded")

        # A record without a fingerprint (older format or unreadable file) never counts.
        (self.root / "records" / "backup.json").write_text(
            json.dumps({"result": "success", "finishedAt": "2026-11-09T03:00:00+00:00"}), encoding="utf-8"
        )
        self.assertIsNone(json.loads(fixture.main("status")[1])["lastBackup"])

    def test_restore_verification_older_than_the_last_backup_says_so(self) -> None:
        fixture = PolicyFixture(self.root)
        fixture.repository("s3:host/bucket")
        early = datetime(2026, 11, 1, 3, 0, tzinfo=timezone.utc)
        late = datetime(2026, 11, 9, 3, 0, tzinfo=timezone.utc)
        status.write_record(fixture.policy, "restore-verify", {"SERVICE_RESULT": "success"}, now=early)
        status.write_record(fixture.policy, "backup", {"SERVICE_RESULT": "success"}, now=late)
        detail = self.rows(json.loads(fixture.main("status")[1]))["restore-verification"]["detail"]
        self.assertIn("latest when verification started", detail)
        self.assertIn("later backups have not been restore-verified", detail)

        status.write_record(fixture.policy, "restore-verify", {"SERVICE_RESULT": "success"}, now=late)
        status.write_record(fixture.policy, "backup", {"SERVICE_RESULT": "success"}, now=early)
        detail = self.rows(json.loads(fixture.main("status")[1]))["restore-verification"]["detail"]
        self.assertNotIn("later backups", detail)

    def test_invalid_utf8_policy_mountinfo_and_records_do_not_crash(self) -> None:
        fixture = PolicyFixture(self.root)
        fixture.repository("b2:bucket:nas")
        records = self.root / "records"
        records.mkdir()
        (records / "backup.json").write_bytes(b"\xff\xfe")
        fixture.mountinfo.write_bytes(b"\xff")
        code, out, _ = fixture.main("status")
        self.assertEqual(code, 0)
        self.assertIsNone(json.loads(out)["lastBackup"])
        fixture.path.write_bytes(b"\xff\xfe")
        code, out, err = fixture.main("status")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("unavailable", err)
        with mock.patch.object(status, "DEFAULT_POLICY_PATH", fixture.path):
            self.assertFalse(status.status_from_environment()["ok"])

    def test_failed_backup_run_is_reported_as_failed(self) -> None:
        fixture = PolicyFixture(self.root)
        fixture.repository("s3:host/bucket")
        env = {"SERVICE_RESULT": "exit-code", "EXIT_CODE": "exited", "EXIT_STATUS": "1"}
        self.assertEqual(fixture.main("record", "backup", env=env)[0], 0)
        value = json.loads(fixture.main("status")[1])
        self.assertFalse(value["ok"])
        self.assertEqual(self.rows(value)["last-backup"]["summary"], "Failed")
        self.assertIn("exit-code", self.rows(value)["last-backup"]["detail"])

    def test_same_pool_repository_is_never_reported_as_independent(self) -> None:
        for overrides, repository in (
            ({}, "/tank/backups/restic"),
            ({"repositorySource": "local", "repositoryFile": None, "allowSamePoolRepository": True}, None),
        ):
            with self.subTest(overrides=overrides):
                fixture = PolicyFixture(self.root, **overrides)
                if repository is not None:
                    fixture.repository(repository)
                env = {"SERVICE_RESULT": "success"}
                self.assertEqual(fixture.main("record", "backup", env=env)[0], 0)
                value = json.loads(fixture.main("status")[1])
                self.assertFalse(value["independentCopyConfigured"])
                self.assertFalse(value["ok"], "a successful same-pool backup is not independent")
                self.assertEqual(self.rows(value)["repository"]["summary"], "Same pool")
                self.assertEqual(self.rows(value)["repository"]["state"], "attention")

    def test_replication_supplies_the_independent_copy_for_a_same_pool_repository(self) -> None:
        fixture = PolicyFixture(
            self.root, repositorySource="local", repositoryFile=None, allowSamePoolRepository=True, replication=True
        )
        self.assertEqual(fixture.main("record", "backup", env={"SERVICE_RESULT": "success"})[0], 0)
        value = json.loads(fixture.main("status")[1])
        self.assertTrue(value["independentCopyConfigured"])
        self.assertTrue(value["ok"])
        self.assertEqual(self.rows(value)["replication"]["state"], "ok")
        self.assertEqual(self.rows(value)["repository"]["summary"], "Same pool")

    def test_disabled_backup_reports_not_configured(self) -> None:
        fixture = PolicyFixture(
            self.root, enabled=False, repositorySource="local", repositoryFile=None, restoreVerification=False
        )
        value = json.loads(fixture.main("status")[1])
        rows = self.rows(value)
        self.assertEqual(rows["repository"]["summary"], "Not configured")
        self.assertNotIn("last-backup", rows)
        self.assertNotIn("restore-verification", rows)
        self.assertFalse(value["ok"])

    def test_system_disk_repository_is_not_independent(self) -> None:
        fixture = PolicyFixture(self.root)
        fixture.repository("/var/lib/restic")
        self.assertEqual(fixture.main("record", "backup", env={"SERVICE_RESULT": "success"})[0], 0)
        value = json.loads(fixture.main("status")[1])
        self.assertFalse(value["independentCopyConfigured"])
        self.assertFalse(value["ok"])
        self.assertEqual(self.rows(value)["repository"]["summary"], "System disk")

    def test_disabled_restore_verification_is_visible(self) -> None:
        fixture = PolicyFixture(self.root, restoreVerification=False)
        fixture.repository("b2:bucket:nas")
        rows = self.rows(json.loads(fixture.main("status")[1]))
        self.assertEqual(rows["restore-verification"]["summary"], "Disabled")

    def test_status_never_prints_the_repository_string(self) -> None:
        fixture = PolicyFixture(self.root)
        fixture.repository(SECRET_REPOSITORY)
        code, out, err = fixture.main("status")
        self.assertEqual(code, 0)
        self.assertNotIn("hunter2", out + err)
        self.assertNotIn("backup.example.test", out + err)
        self.assertEqual(json.loads(out)["repository"]["backend"], "rest")

    def test_unreadable_or_malformed_repository_file_is_unavailable(self) -> None:
        fixture = PolicyFixture(self.root)
        value = json.loads(fixture.main("status")[1])
        self.assertEqual(self.rows(value)["repository"]["state"], "unavailable")
        for content in ("", "\n", "rclone:a\nrclone:b\n", "x" * 5000):
            with self.subTest(content=content[:20]):
                fixture.repository(content)
                value = json.loads(fixture.main("status")[1])
                self.assertEqual(value["repository"]["location"], "unavailable")
                self.assertFalse(value["independentCopyConfigured"])

    def test_policy_errors_fail_closed(self) -> None:
        fixture = PolicyFixture(self.root)
        for policy in ("{broken", json.dumps({"schemaVersion": 2}), json.dumps({**fixture.policy, "enabled": "yes"})):
            with self.subTest(policy=policy[:30]):
                fixture.path.write_text(policy, encoding="utf-8")
                code, out, err = fixture.main("status")
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("nas-backup-status:", err)
        relative = {**fixture.policy, "repositoryFile": "relative/file"}
        fixture.path.write_text(json.dumps(relative), encoding="utf-8")
        self.assertEqual(fixture.main("check-readiness")[0], 2)

    def test_overview_status_reports_a_missing_policy_explicitly(self) -> None:
        with mock.patch.object(status, "DEFAULT_POLICY_PATH", self.root / "absent.json"):
            value = status.status_from_environment()
        self.assertFalse(value["ok"])
        self.assertIn("unavailable", value["error"])
        self.assertEqual(value["rows"], [])


class ReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_readiness_matrix(self) -> None:
        cases = (
            ("network repository", {}, "rclone:gdrive:nas-backup", 0, ""),
            ("off-pool local disk", {}, "/mnt/usb disk/restic", 0, ""),
            ("backup disk not yet mounted", {}, "/mnt/usb/restic", 0, ""),
            ("same-pool repository file", {}, "/tank/backups/restic", 1, "managed ZFS pool"),
            ("same-pool local: prefix", {}, "local:/srv/apps/restic", 1, "managed ZFS pool"),
            ("relative repository", {}, "restic", 1, "absolute local path"),
            ("backend without destination", {}, "rclone:", 1, "with a destination"),
            ("tmpfs repository", {}, "/run/restic", 1, "lost at reboot"),
            ("unverifiable mount", {"mountinfo": ""}, "/mnt/usb/restic", 1, "could not be determined"),
            ("missing repository file", {}, None, 1, "unreadable"),
            ("replication covers same-pool", {"replication": True}, "/tank/backups/restic", 0, ""),
            (
                "local repository without replication",
                {"repositorySource": "local", "repositoryFile": None, "allowSamePoolRepository": True},
                None,
                1,
                "off-pool Restic repository",
            ),
            (
                "backup disabled without replication",
                {"enabled": False, "repositorySource": "local", "repositoryFile": None},
                None,
                1,
                "off-pool Restic repository",
            ),
        )
        for name, overrides, repository, expected, message in cases:
            with self.subTest(name):
                case_root = self.root / name.replace(" ", "-")
                case_root.mkdir()
                overrides = dict(overrides)
                mountinfo = overrides.pop("mountinfo", None)
                fixture = PolicyFixture(case_root, **overrides)
                if mountinfo is not None:
                    fixture.mountinfo.write_text(str(mountinfo), encoding="utf-8")
                if repository is not None:
                    fixture.repository(repository)
                code, out, err = fixture.main("check-readiness")
                self.assertEqual(code, expected, err)
                self.assertEqual(out, "")
                self.assertIn(message, err)
                if repository:
                    self.assertNotIn(repository, err)


class RecordTests(unittest.TestCase):
    def test_record_requires_systemd_result_and_writes_a_readable_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = PolicyFixture(pathlib.Path(raw))
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SERVICE_RESULT", None)
                code, _, err = fixture.main("record", "backup")
            self.assertEqual(code, 2)
            self.assertIn("ExecStopPost", err)
            self.assertFalse((pathlib.Path(raw) / "records" / "backup.json").exists())

            moment = datetime(2026, 11, 9, 3, 0, tzinfo=timezone.utc)
            record = status.write_record(fixture.policy, "backup", {"SERVICE_RESULT": "timeout"}, now=moment)
            path = pathlib.Path(raw) / "records" / "backup.json"
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), record)
            self.assertEqual(record["finishedAt"], "2026-11-09T03:00:00+00:00")
            # The record holds a fingerprint of a possibly secret repository string.
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertNotIn(str(fixture.repository_file), path.read_text(encoding="utf-8"))
            self.assertEqual(list(path.parent.glob(".*")), [])
            with self.assertRaises(status.BackupStatusError):
                status.write_record(fixture.policy, "../escape", {"SERVICE_RESULT": "success"})
            with self.assertRaises(SystemExit):
                fixture.main("record", "other")

    def test_corrupt_record_is_treated_as_no_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = PolicyFixture(pathlib.Path(raw))
            records = pathlib.Path(raw) / "records"
            records.mkdir()
            for content in ("{broken", "[]", json.dumps({"result": "success"})):
                with self.subTest(content=content):
                    (records / "backup.json").write_text(content, encoding="utf-8")
                    self.assertIsNone(status.read_record(fixture.policy, "backup"))


class NixWiringTests(unittest.TestCase):
    """Keep the Nix-written policy and unit hooks aligned with this CLI."""

    def runtime_keys(self) -> set[str]:
        policy = (ROOT / "modules/nas/internal/backup-policy.nix").read_text(encoding="utf-8")
        block = policy.split("  runtime = {", 1)[1].split("\n  };", 1)[0]
        keys: set[str] = set()
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("inherit "):
                keys.update(line.removeprefix("inherit ").rstrip(";").split())
            elif "=" in line:
                keys.add(line.split("=", 1)[0].strip())
        return keys

    def test_nix_runtime_policy_has_exactly_the_fields_the_cli_loads(self) -> None:
        keys = self.runtime_keys()
        self.assertEqual(
            keys,
            {
                "schemaVersion",
                "enabled",
                "repositorySource",
                "localRepository",
                "repositoryFile",
                "allowSamePoolRepository",
                "replication",
                "restoreVerification",
                "zfsPool",
                "zfsRoot",
                "recordDirectory",
            },
        )
        with tempfile.TemporaryDirectory() as raw:
            fixture = PolicyFixture(pathlib.Path(raw))
            self.assertEqual(set(fixture.policy), keys)
            for key in sorted(keys - {"repositoryFile"}):
                with self.subTest(missing=key):
                    reduced = {name: value for name, value in fixture.policy.items() if name != key}
                    fixture.path.write_text(json.dumps(reduced), encoding="utf-8")
                    with self.assertRaises(status.BackupStatusError):
                        status.load_policy(fixture.path)

    def test_units_record_results_and_readiness_checks_location(self) -> None:
        storage = (ROOT / "modules/nas/config/storage-monitoring.nix").read_text(encoding="utf-8")
        readiness = (ROOT / "modules/nas/config/install-readiness.nix").read_text(encoding="utf-8")
        self.assertIn(
            'environment.etc."nas-control/backup-policy.json".text = builtins.toJSON backupPolicy.runtime;', storage
        )
        backup_unit = storage.split("systemd.services.restic-backups-nas-boot-system =", 1)[1].split(
            "systemd.services.", 1
        )[0]
        verify_unit = storage.split("systemd.services.nas-backup-restore-verify =", 1)[1].split("script = ''", 1)[0]
        # The leading dash keeps a recording failure from changing the run result.
        self.assertIn('"-${nasBackupStatus}/bin/nas-backup-status record backup"', backup_unit)
        self.assertIn('"-${nasBackupStatus}/bin/nas-backup-status record restore-verify"', verify_unit)
        self.assertIn("${nasInternal.nasBackupStatus}/bin/nas-backup-status check-readiness", readiness)
        self.assertNotIn("backup.remote", storage + readiness)
        self.assertEqual(set(status.RECORD_NAMES), {"backup", "restore-verify"})


if __name__ == "__main__":
    unittest.main()
