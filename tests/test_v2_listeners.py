"""Consolidated listeners suites (merged from 2 micro-files)."""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_quadlet as quadlet  # noqa: E402


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
