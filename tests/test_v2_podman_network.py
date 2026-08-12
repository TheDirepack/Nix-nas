from __future__ import annotations

import pathlib
import stat
import sys
import tempfile
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

    def fake_nmcli(self, root: pathlib.Path) -> str:
        script = root / "nmcli"
        script.write_text(
            "#!/bin/sh\n"
            'case " $* " in\n'
            "  *\" --offline \"*) printf '[connection]\\nid=fake\\n' ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return str(script)

    def project_vlan(
        self, effective: dict, output: pathlib.Path, *, nmcli: str
    ) -> tuple[dict[pathlib.Path, bytes], dict]:
        files: dict[pathlib.Path, bytes] = {}
        manifest = {"quadletLinks": [], "links": [], "ownedUnits": [], "startUnits": []}
        network.augment_projection(
            effective,
            output_dir=output,
            files=files,
            manifest=manifest,
            nmcli_bin=nmcli,
            install_bin="/bin/install",
            rm_bin="/bin/rm",
        )
        return files, manifest

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

    def test_isolated_vlan_uses_shared_vrf_and_networkmanager_uplink(self):
        effective, service = self.service(
            policy={
                "mode": "isolated",
                "vlanId": 42,
                "vlanParent": "eno1",
                "outboundDefault": "allow",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            }
        )
        vlan = network.vlan_binding(service["network"])
        assert vlan is not None
        with tempfile.TemporaryDirectory() as raw:
            nmcli = self.fake_nmcli(pathlib.Path(raw))
            output = pathlib.Path("/run/nas-control/systemd")
            files, manifest = self.project_vlan(effective, output, nmcli=nmcli)

        rendered = files[output / "quadlet/nas-v2-net-demo.network"].decode()
        self.assertIn("Driver=bridge", rendered)
        self.assertIn("Options=isolate=strict", rendered)
        self.assertIn(f"Options=vrf={vlan['vrfInterface']}", rendered)
        self.assertIn(f"Requires={vlan['unit']}", rendered)
        self.assertNotIn("Options=vlan=42", rendered)

        vlan_unit = files[output / "units" / vlan["unit"]].decode()
        self.assertIn("Requires=NetworkManager.service", vlan_unit)
        self.assertIn("StopWhenUnneeded=yes", vlan_unit)
        self.assertIn(f"connection up id {vlan['vrfProfile']}", vlan_unit)
        self.assertIn(f"connection up id {vlan['vlanProfile']}", vlan_unit)
        self.assertIn(vlan["unit"], manifest["ownedUnits"])
        self.assertNotIn(vlan["unit"], manifest["startUnits"])
        self.assertIn(output / "networkmanager" / f"{vlan['vrfProfile']}.nmconnection", files)
        self.assertIn(output / "networkmanager" / f"{vlan['vlanProfile']}.nmconnection", files)

    def test_network_profile_can_supply_physical_vlan(self):
        effective, service = self.service()
        service.pop("network")
        service["networkProfile"] = "media"
        effective["networkProfiles"] = {
            "media": {
                "mode": "isolated",
                "vlanId": 120,
                "vlanParent": "enp4s0",
                "outboundDefault": "allow",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            }
        }
        vlan = network.vlan_binding(effective["networkProfiles"]["media"])
        assert vlan is not None
        with tempfile.TemporaryDirectory() as raw:
            nmcli = self.fake_nmcli(pathlib.Path(raw))
            output = pathlib.Path("/run/nas-control/systemd")
            files, _manifest = self.project_vlan(effective, output, nmcli=nmcli)
        rendered = files[output / "quadlet/nas-v2-net-demo.network"].decode()
        self.assertIn(f"Options=vrf={vlan['vrfInterface']}", rendered)

    def test_services_share_same_vlan_uplink_resource(self):
        policy = {
            "mode": "isolated",
            "vlanId": 55,
            "vlanParent": "eno1",
            "outboundDefault": "allow",
            "lanAccess": False,
            "allowedHostPorts": [],
            "allowedEgress": [],
        }
        effective, first = self.service(policy=policy)
        second = {**first, "name": "second"}
        effective["services"]["second"] = second
        effective["derived"]["runtime"]["second"] = {"ownerUnit": "nas-v2-second.service"}
        vlan = network.vlan_binding(policy)
        assert vlan is not None
        with tempfile.TemporaryDirectory() as raw:
            nmcli = self.fake_nmcli(pathlib.Path(raw))
            output = pathlib.Path("/run/nas-control/systemd")
            _files, manifest = self.project_vlan(effective, output, nmcli=nmcli)
        self.assertEqual(manifest["ownedUnits"].count(vlan["unit"]), 1)
        self.assertEqual(
            sum(1 for item in manifest["links"] if item["target"] == vlan["unit"]),
            1,
        )

    def test_vlan_pair_is_required_and_validated_defensively(self):
        invalid = [
            {"vlanId": 42},
            {"vlanParent": "eno1"},
            {"vlanId": 0, "vlanParent": "eno1"},
            {"vlanId": 4095, "vlanParent": "eno1"},
            {"vlanId": True, "vlanParent": "eno1"},
            {"vlanId": 42, "vlanParent": "bad interface"},
        ]
        for extra in invalid:
            policy = {
                "mode": "isolated",
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
                **extra,
            }
            with self.subTest(extra=extra), self.assertRaises(network.PodmanNetworkProjectionError):
                network.vlan_binding(policy)

    def test_vlan_fails_closed_for_host_and_none_networks(self):
        for mode in ("host", "none"):
            effective, service = self.service(
                policy={
                    "mode": mode,
                    "vlanId": 77,
                    "vlanParent": "eno1",
                    "outboundDefault": "allow" if mode == "host" else "deny",
                    "lanAccess": False,
                    "allowedHostPorts": [],
                    "allowedEgress": [],
                }
            )
            with self.subTest(mode=mode), self.assertRaises(network.PodmanNetworkProjectionError):
                network.quadlet_network_reference(effective, "demo", service)

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
