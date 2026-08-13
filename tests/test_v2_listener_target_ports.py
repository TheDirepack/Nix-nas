from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_quadlet as quadlet  # noqa: E402


class ManagedServicesV2ListenerTargetPortTests(unittest.TestCase):
    def service(self) -> tuple[dict, dict]:
        service = {
            "managed": True,
            "workload": {"kind": "daemon", "activation": "persistent"},
            "runtime": {
                "type": "oci",
                "image": "example.invalid/demo:1",
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
            "listeners": {},
            "routes": {},
            "storage": [],
            "credentials": [],
            "sandbox": {"mode": "inherit"},
            "resources": {"accelerators": []},
        }
        effective = {
            "services": {"demo": service},
            "networkProfiles": {},
            "derived": {"runtime": {"demo": {"ownerUnit": "nas-v2-demo.service"}}},
        }
        return effective, service

    def test_single_listener_maps_external_to_target_port(self) -> None:
        effective, service = self.service()
        service["listeners"] = {
            "web": {
                "protocol": "tcp",
                "exposure": {"port": 8080},
                "targetPort": 80,
                "firewall": True,
            }
        }
        rendered = quadlet.render_quadlet(
            effective,
            "demo",
            service,
            unit_lines=[],
            service_lines=[],
        ).decode()
        self.assertIn('PublishPort="8080:80/tcp"', rendered)
        self.assertNotIn('PublishPort="8080:8080/tcp"', rendered)

    def test_listener_without_target_port_keeps_same_port_mapping(self) -> None:
        effective, service = self.service()
        service["listeners"] = {
            "web": {
                "protocol": "tcp",
                "exposure": {"port": 8080},
                "firewall": True,
            }
        }
        rendered = quadlet.render_quadlet(
            effective,
            "demo",
            service,
            unit_lines=[],
            service_lines=[],
        ).decode()
        self.assertIn('PublishPort="8080:8080/tcp"', rendered)

    def test_target_port_is_rejected_for_listener_ranges(self) -> None:
        effective, service = self.service()
        service["listeners"] = {
            "range": {
                "protocol": "udp",
                "exposure": {"start": 5000, "end": 5005},
                "targetPort": 6000,
                "firewall": True,
            }
        }
        with self.assertRaisesRegex(quadlet.QuadletProjectionError, "single exposed port"):
            quadlet.render_quadlet(
                effective,
                "demo",
                service,
                unit_lines=[],
                service_lines=[],
            )


if __name__ == "__main__":
    unittest.main()
