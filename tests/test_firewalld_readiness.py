from __future__ import annotations

import unittest

from repo_test_utils import text


class FirewalldReadinessTests(unittest.TestCase):
    def test_firewall_dependents_wait_for_the_native_dbus_api(self) -> None:
        firewall = text("modules/nas/config/network-firewall.nix")
        daemon = firewall.split("systemd.services.firewalld =", 1)[1].split(
            "systemd.services.nas-firewall-baseline =", 1
        )[0]
        self.assertIn('Type = "dbus";', daemon)
        self.assertIn('BusName = "org.fedoraproject.FirewallD1";', daemon)

    def test_native_vm_restarts_the_daemon_and_baseline_in_one_ordered_transaction(self) -> None:
        native = text("tests/nixos/integration.nix")
        self.assertIn("systemctl restart firewalld.service nas-firewall-baseline.service", native)
        self.assertIn("systemctl is-active --quiet nas-firewall-baseline.service", native)
