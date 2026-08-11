from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "modules" / "nas" / "config" / "managed-services-operational-schedules.nix"


class ManagedServicesV2OperationalScheduleTests(unittest.TestCase):
    def test_v1_operational_timers_are_represented_as_v2_jobs(self) -> None:
        module = MODULE.read_text(encoding="utf-8")
        expected = {
            "nas-zfs-pool-health.service": "*-*-* 06:00",
            "nas-zfs-capacity-health.service": "*-*-* 06:00",
            "nas-zfs-snapshot-health.service": "*-*-* 06:00",
            "nas-auto-update.service": "cfg.autoUpdate.onCalendar",
            "restic-backups-nas-boot-system.service": 'calendar = "daily"',
            "nas-backup-restore-verify.service": "cfg.backup.restoreVerification.onCalendar",
            "nas-syncoid.service": "cfg.zfsReplication.onCalendar",
        }
        for unit, schedule in expected.items():
            with self.subTest(unit=unit):
                self.assertIn(unit, module)
                self.assertIn(schedule, module)
        self.assertIn('markerPath = "/var/lib/nas-control/.managed-services-operational-schedules-seed-v2"', module)
        self.assertIn("nas_v2_bootstrap.py", module)

    def test_restic_native_timer_is_not_a_second_scheduler(self) -> None:
        module = MODULE.read_text(encoding="utf-8")
        self.assertIn("nas-boot-system.timerConfig = lib.mkForce null", module)
        self.assertNotIn("systemd.timers", module)

    def test_module_is_part_of_the_nas_configuration(self) -> None:
        root_module = (ROOT / "modules" / "nas" / "default.nix").read_text(encoding="utf-8")
        self.assertIn("./config/managed-services-operational-schedules.nix", root_module)


if __name__ == "__main__":
    unittest.main()
