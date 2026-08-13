from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_firewalld as firewalld  # noqa: E402


class V2ComposeFirewalldTests(unittest.TestCase):
    def test_targeted_compose_ingress_uses_exposed_listener_and_route_ports(self) -> None:
        service = {
            "managed": True,
            "enabled": True,
            "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/demo/compose.yaml"},
            "workload": {"kind": "daemon", "activation": "persistent"},
            "network": {
                "mode": "isolated",
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            },
            "routes": {
                "web": {
                    "runtimeTarget": "web",
                    "target": {"type": "http", "host": "127.0.0.1", "port": 8081},
                    "exposure": {"type": "path", "paths": ["/demo"]},
                    "auth": {"mode": "public"},
                }
            },
            "listeners": {
                "api": {
                    "protocol": "tcp",
                    "exposure": {"port": 18080},
                    "runtimeTarget": "web",
                    "firewall": True,
                },
                "discovery": {
                    "protocol": "udp",
                    "exposure": {"start": 19000, "end": 19002},
                    "runtimeTarget": "worker",
                    "firewall": True,
                },
            },
        }
        effective = {"services": {"demo": service}, "networkProfiles": {}}

        files, _manifest = firewalld.compile_projection(effective, lan_zone="nas-trusted")
        listener = files[f"policies/{firewalld.listener_policy_name('demo')}.xml"].decode()
        route = files[f"policies/{firewalld.route_policy_name('demo')}.xml"].decode()

        self.assertIn('port="18080" protocol="tcp"', listener)
        self.assertIn('port="19000-19002" protocol="udp"', listener)
        self.assertNotIn('port="8080" protocol="tcp"', listener)
        self.assertIn('<ingress-zone name="HOST"/>', route)
        self.assertIn('port="8081" protocol="tcp"', route)


if __name__ == "__main__":
    unittest.main()
