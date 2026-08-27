"""Contracts for the installed two-reboot setup lifecycle runner."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests/vm/setup-reboot-e2e.py"


class SetupRebootE2eContracts(unittest.TestCase):
    def test_runner_rechecks_storage_v2_apps_and_authenticated_routes_after_each_reboot(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"after-first-reboot"', source)
        self.assertIn('"after-second-reboot"', source)
        self.assertIn('verifiedReboots=2', source)
        self.assertIn('"copyparty.service"', source)
        self.assertIn('"syncthing.service"', source)
        self.assertIn('"vaultwarden.service"', source)
        self.assertIn('"grafana.service"', source)
        self.assertIn('"nas-managed-services-control", "status"', source)
        self.assertIn('"tests/browser/authz.py"', source)
        self.assertIn('"/tank/shares/e2e-reboot-sentinel.txt"', source)
        self.assertIn('lib/systemd/systemd-socket-proxyd', source)
        self.assertIn('--resolve", "nas-test.local:8443:127.0.0.1', source)

    def test_runner_resumes_through_a_transient_vm_only_systemd_unit(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('nas-vm-setup-reboot-e2e.service', source)
        self.assertIn('nas-vm-guest-test --setup-reboot-e2e --resume', source)
        self.assertIn('WantedBy=multi-user.target', source)
        self.assertIn('f"--unit=nas-vm-setup-reboot-e2e-{next_phase}"', source)
        self.assertIn('After=network-online.target', source)
        self.assertIn('"systemctl", "disable", UNIT.name', source)


if __name__ == "__main__":
    unittest.main()
