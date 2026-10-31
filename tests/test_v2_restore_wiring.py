from __future__ import annotations

import pathlib
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class V2RestoreWiringTests(unittest.TestCase):
    def test_restore_verification_is_resource_oriented(self):
        storage = (ROOT / "modules/nas/config/storage-monitoring.nix").read_text(encoding="utf-8")

        self.assertIn("nas_v2_backup.py", storage)
        self.assertNotIn("nas_v2_backup_verify.py", storage)
        self.assertIn("--inventory ${lib.escapeShellArg v2BackupInventory}", storage)
        self.assertIn('--restore-root "$restore_root"', storage)
        self.assertIn("--pg-restore ${config.services.postgresql.package}/bin/pg_restore", storage)

        for application_specific_fragment in (
            "django_migrations",
            "authentik_core_user",
            '"$staged"/copyparty/*.db',
            "syncthingConfigDir",
            "ET.parse",
            "pg_ctl",
            "authentik_verify",
        ):
            with self.subTest(fragment=application_specific_fragment):
                self.assertNotIn(application_specific_fragment, storage)

    def test_recovery_substrate_checks_use_restored_paths_and_literal_dollars(self):
        storage = (ROOT / "modules/nas/config/storage-monitoring.nix").read_text(encoding="utf-8")
        secret_check = next(
            line.strip() for line in storage.splitlines()
            if '[[ -s "$restore_root"' in line
        )
        control_check = next(
            line.strip() for line in storage.splitlines()
            if '[[ -d "$restore_root"' in line
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            zfs_root = root / "nas$archive"
            live_control = zfs_root / "nas-control"
            live_secret = zfs_root / "secrets" / "db$literal.kdbx"
            live_control.mkdir(parents=True)
            live_secret.parent.mkdir(parents=True)
            live_secret.write_bytes(b"live-only")
            restore_root = root / "restore"
            restore_root.mkdir()
            checks = (
                secret_check.replace(
                    "${lib.escapeShellArg cfg.secrets.keepassDatabase}", shlex.quote(str(live_secret))
                ).replace(
                    '${lib.escapeShellArg "${cfg.zfsRoot}/nas-control"}',
                    shlex.quote(str(zfs_root / "nas-control")),
                )
                + "\n"
                + control_check.replace(
                    "${lib.escapeShellArg cfg.secrets.keepassDatabase}", shlex.quote(str(live_secret))
                ).replace(
                    '${lib.escapeShellArg "${cfg.zfsRoot}/nas-control"}',
                    shlex.quote(str(zfs_root / "nas-control")),
                )
            )
            self.assertNotIn("${lib.escapeShellArg", checks)
            command = "set -euo pipefail\nrestore_root=" + shlex.quote(str(restore_root)) + "\n" + checks
            # Live paths exist but the recovered payload is absent: must fail.
            missing = subprocess.run(
                ["bash", "-c", command], check=False, capture_output=True, text=True, timeout=5
            )
            self.assertNotEqual(missing.returncode, 0)

            recovered_control = pathlib.Path(str(restore_root) + str(live_control))
            recovered_secret = pathlib.Path(str(restore_root) + str(live_secret))
            recovered_control.mkdir(parents=True)
            recovered_secret.parent.mkdir(parents=True, exist_ok=True)
            recovered_secret.write_bytes(b"restored")
            present = subprocess.run(
                ["bash", "-c", command], check=False, capture_output=True, text=True, timeout=5
            )
            self.assertEqual(present.returncode, 0, present.stdout + present.stderr)

    def test_verifier_has_no_application_name_branches(self):
        verifier = (ROOT / "services/nas_v2_backup.py").read_text(encoding="utf-8")
        for application_name in ("authentik", "copyparty", "syncthing", "vaultwarden"):
            with self.subTest(application=application_name):
                self.assertNotIn(application_name, verifier.lower())


if __name__ == "__main__":
    unittest.main()
