from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_network as firewalld  # noqa: E402
import nas_v2_quadlet as quadlet  # noqa: E402
from nas_v2_network import requires_firewalld  # noqa: E402


class V2GenericListenerTests(unittest.TestCase):
    def test_arbitrary_native_service_can_publish_mixed_listener_set(self):
        service = {
            "managed": False,
            "enabled": True,
            "runtime": {"type": "systemd", "unit": "custom-discovery.service"},
            "network": {
                "mode": "host",
                "outboundDefault": "allow",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            },
            "listeners": {
                "control": {
                    "protocol": "tcp",
                    "exposure": {"port": 17321},
                    "firewall": True,
                },
                "discovery": {
                    "protocol": "udp",
                    "exposure": {"port": 17322},
                    "firewall": True,
                },
                "transfer-range": {
                    "protocol": "udp",
                    "exposure": {"start": 17330, "end": 17339},
                    "firewall": True,
                },
                "private": {
                    "protocol": "tcp",
                    "exposure": {"port": 17340},
                    "firewall": False,
                },
            },
        }
        effective = {"schemaVersion": 3, "services": {"custom-discovery": service}, "networkProfiles": {}}

        self.assertTrue(requires_firewalld(effective))
        files, manifest = firewalld.compile_projection(effective, lan_zone="trusted")
        target = f"policies/{firewalld.listener_policy_name('custom-discovery')}.xml"
        policy = files[target].decode()

        self.assertIn('port="17321" protocol="tcp"', policy)
        self.assertIn('port="17322" protocol="udp"', policy)
        self.assertIn('port="17330-17339" protocol="udp"', policy)
        self.assertNotIn('port="17340"', policy)
        self.assertEqual(manifest["owners"], [{"service": "custom-discovery", "target": target}])

    def test_arbitrary_host_service_can_remap_privileged_listener(self):
        service = {
            "managed": True,
            "enabled": True,
            "runtime": {"type": "systemd", "unit": "custom-daemon.service"},
            "network": {
                "mode": "host",
                "outboundDefault": "allow",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            },
            "listeners": {
                "legacy-protocol": {
                    "protocol": "udp",
                    "exposure": {"port": 137},
                    "targetPort": 10137,
                    "firewall": True,
                }
            },
        }
        effective = {"schemaVersion": 3, "services": {"custom-daemon": service}, "networkProfiles": {}}

        files, _manifest = firewalld.compile_projection(effective, lan_zone="trusted")
        policy = files[f"policies/{firewalld.listener_policy_name('custom-daemon')}.xml"].decode()
        self.assertIn('forward-port port="137" protocol="udp" to-port="10137"', policy)

    def test_arbitrary_isolated_oci_service_publishes_listener_without_app_branching(self):
        service = {
            "managed": True,
            "enabled": True,
            "workload": {"kind": "daemon", "activation": "persistent"},
            "runtime": {
                "type": "oci",
                "image": "example.invalid/custom:1",
                "pull": "missing",
                "command": [],
            },
            "network": {
                "mode": "isolated",
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            },
            "listeners": {
                "api": {
                    "protocol": "tcp",
                    "exposure": {"port": 18443},
                    "targetPort": 8443,
                    "firewall": True,
                },
                "discovery": {
                    "protocol": "udp",
                    "exposure": {"port": 19000},
                    "firewall": True,
                },
            },
            "routes": {},
            "storage": [],
            "credentials": [],
            "sandbox": {"mode": "inherit"},
            "resources": {"accelerators": []},
        }
        effective = {
            "schemaVersion": 3,
            "services": {"custom-container": service},
            "networkProfiles": {},
            "derived": {"runtime": {"custom-container": {"ownerUnit": "nas-v2-custom-container.service"}}},
        }

        rendered = quadlet.render_quadlet(
            effective,
            "custom-container",
            service,
            unit_lines=[],
            service_lines=[],
        ).decode()
        self.assertIn('PublishPort="18443:8443/tcp"', rendered)
        self.assertIn('PublishPort="19000:19000/udp"', rendered)


if __name__ == "__main__":
    unittest.main()
