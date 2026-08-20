from __future__ import annotations

import pathlib
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

    def test_verifier_has_no_application_name_branches(self):
        verifier = (ROOT / "services/nas_v2_backup.py").read_text(encoding="utf-8")
        for application_name in ("authentik", "copyparty", "syncthing", "vaultwarden"):
            with self.subTest(application=application_name):
                self.assertNotIn(application_name, verifier.lower())


if __name__ == "__main__":
    unittest.main()
