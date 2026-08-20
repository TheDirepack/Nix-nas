from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ManagedServicesV2NativeListenerTests(unittest.TestCase):
    def test_direct_application_ingress_lives_in_v2_seed(self) -> None:
        seed = (ROOT / "modules" / "nas" / "config" / "managed-services-seed-v2.nix").read_text(encoding="utf-8")
        self.assertIn('sync-tcp = portListener "tcp" syncthingSyncPort;', seed)
        self.assertIn('sync-quic = portListener "udp" syncthingSyncPort;', seed)
        self.assertIn('local-discovery = portListener "udp" syncthingDiscoveryPort;', seed)
        self.assertIn('daemon "upsd.service" "NUT UPS network server"', seed)
        self.assertIn('listeners.nut = portListener "tcp" nutUpsdPort;', seed)
        self.assertIn('platformService ((daemon "upsd.service"', seed)
        self.assertIn("listeners = lib.optionalAttrs cfg.tftp.enable", seed)
        self.assertIn('tftp-request = (portListener "udp" cfg.tftp.port)', seed)
        self.assertIn("targetPort = cfg.tftp.internalPort;", seed)
        self.assertIn("start = cfg.tftp.responsePortStart;", seed)
        self.assertIn("end = cfg.tftp.responsePortEnd;", seed)

    def test_host_firewall_baseline_no_longer_owns_application_ports(self) -> None:
        firewall = (ROOT / "modules" / "nas" / "config" / "network-firewall.nix").read_text(encoding="utf-8")
        for stale in (
            'port = "22000";',
            'port = "21027";',
            'port = "3493";',
            "cfg.syncthing.enable",
            'cfg.power.ups.mode == "netserver"',
            "cfg.tftp.enable",
            "cfg.tftp.port",
            "cfg.tftp.internalPort",
            "cfg.tftp.responsePortStart",
            "cfg.tftp.responsePortEnd",
        ):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, firewall)


if __name__ == "__main__":
    unittest.main()
