from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_podman_network as network  # noqa: E402
import nas_v2_quadlet as quadlet  # noqa: E402
import nas_v2_systemd_reconcile as reconcile  # noqa: E402


class V2PodmanNetworkTests(unittest.TestCase):
    def service(self, *, policy: dict | None = None) -> tuple[dict, dict]:
        service = {
            "managed": True,
            "workload": {"kind": "daemon", "activation": "persistent"},
            "runtime": {
                "type": "oci",
                "image": "example.invalid/demo:1",
                "pull": "missing",
                "command": [],
            },
            "network": policy
            or {
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

    def test_deny_all_isolated_policy_uses_native_quadlet_network(self):
        effective, service = self.service()
        self.assertEqual(
            network.quadlet_network_reference(effective, "demo", service),
            "nas-v2-net-demo.network",
        )

        files: dict[pathlib.Path, bytes] = {}
        manifest = {"quadletLinks": []}
        output = pathlib.Path("/run/nas-control/systemd")
        network.augment_projection(effective, output_dir=output, files=files, manifest=manifest)

        source = output / "quadlet/nas-v2-net-demo.network"
        rendered = files[source].decode()
        self.assertIn("PartOf=nas-v2-demo.service", rendered)
        self.assertIn("NetworkName=nas-v2-demo", rendered)
        self.assertIn("Driver=bridge", rendered)
        self.assertIn("Internal=true", rendered)
        self.assertIn("Options=isolate=strict", rendered)
        self.assertIn("NetworkDeleteOnStop=true", rendered)
        self.assertEqual(
            manifest["quadletLinks"],
            [{"target": "nas-v2-net-demo.network", "source": str(source)}],
        )

    def test_disabled_service_projects_no_network_or_firewalld_requirement(self):
        effective, service = self.service()
        service["enabled"] = False
        service["listeners"] = {
            "web": {"protocol": "tcp", "exposure": {"port": 8080}, "firewall": True},
        }
        files: dict[pathlib.Path, bytes] = {}
        manifest = {"quadletLinks": []}
        network.augment_projection(
            effective,
            output_dir=pathlib.Path("/run/nas-control/systemd"),
            files=files,
            manifest=manifest,
        )
        self.assertFalse(network.requires_firewalld(effective))
        self.assertEqual({}, files)
        self.assertEqual([], manifest["quadletLinks"])

    def test_oci_quadlet_references_generated_network_unit(self):
        effective, service = self.service()
        rendered = quadlet.render_quadlet(
            effective,
            "demo",
            service,
            unit_lines=["Description=Demo"],
            service_lines=[],
        ).decode()
        self.assertIn("Network=nas-v2-net-demo.network", rendered)

    def test_network_profile_can_drive_native_isolation(self):
        effective, service = self.service()
        policy = service.pop("network")
        service["networkProfile"] = "locked"
        effective["networkProfiles"] = {"locked": policy}
        self.assertEqual(
            network.quadlet_network_reference(effective, "demo", service),
            "nas-v2-net-demo.network",
        )

    def test_rich_isolation_requires_firewalld_at_apply_boundary(self):
        for policy in (
            {
                "mode": "isolated",
                "outboundDefault": "allow",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            },
            {
                "mode": "isolated",
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [{"cidr": "1.1.1.1/32", "ports": [443]}],
            },
        ):
            with self.subTest(policy=policy):
                effective, service = self.service(policy=policy)
                self.assertTrue(network.requires_firewalld(effective))
                with self.assertRaisesRegex(network.PodmanNetworkProjectionError, "firewalld policy projection"):
                    network.quadlet_network_reference(effective, "demo", service, firewalld_enabled=False)

    def test_isolated_listener_is_published_and_requires_firewalld_when_managed(self):
        effective, service = self.service()
        service["listeners"] = {
            "web": {"protocol": "tcp", "exposure": {"port": 8080}, "firewall": True},
            "dns": {"protocol": "udp", "exposure": {"start": 5300, "end": 5302}, "firewall": False},
        }
        self.assertTrue(network.requires_firewalld(effective))
        rendered = quadlet.render_quadlet(
            effective,
            "demo",
            service,
            unit_lines=[],
            service_lines=[],
        ).decode()
        self.assertIn('PublishPort="8080:8080/tcp"', rendered)
        self.assertIn('PublishPort="5300-5302:5300-5302/udp"', rendered)

    def test_isolated_route_is_loopback_published(self):
        effective, service = self.service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "host": "127.0.0.1", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity", "capability": "access"},
                "proxy": {},
                "portal": {},
            }
        }
        self.assertTrue(network.requires_firewalld(effective))
        rendered = quadlet.render_quadlet(
            effective,
            "demo",
            service,
            unit_lines=[],
            service_lines=[],
        ).decode()
        self.assertIn('PublishPort="127.0.0.1:8080:8080/tcp"', rendered)

    def test_network_quadlet_changes_are_attributed_to_workload_owner(self):
        target, affected = reconcile._safe_quadlet_target(
            pathlib.Path("/run/containers/systemd"),
            "nas-v2-net-demo.network",
        )
        self.assertEqual(target, pathlib.Path("/run/containers/systemd/nas-v2-net-demo.network"))
        self.assertEqual(affected, "nas-v2-demo.service")


if __name__ == "__main__":
    unittest.main()
