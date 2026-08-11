from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ManagedServicesV2NativeListenerTests(unittest.TestCase):
    def test_syncthing_and_nut_ingress_live_in_v2_seed(self) -> None:
        seed = (ROOT / "modules" / "nas" / "config" / "managed-services-native-services.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn('sync-tcp = portListener "tcp" 22000;', seed)
        self.assertIn('sync-quic = portListener "udp" 22000;', seed)
        self.assertIn('local-discovery = portListener "udp" 21027;', seed)
        self.assertIn('daemon "upsd.service" "NUT UPS network server"', seed)
        self.assertIn('listeners.nut = portListener "tcp" 3493;', seed)
        self.assertIn('platformService ((daemon "upsd.service"', seed)

    def test_host_firewall_baseline_no_longer_owns_migrated_application_ports(self) -> None:
        firewall = (ROOT / "modules" / "nas" / "config" / "network-firewall.nix").read_text(encoding="utf-8")
        for stale in (
            'port = "22000";',
            'port = "21027";',
            'port = "3493";',
            "cfg.syncthing.enable",
            'cfg.power.ups.mode == "netserver"',
        ):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, firewall)
        self.assertIn("cfg.tftp.enable", firewall)


if __name__ == "__main__":
    unittest.main()
