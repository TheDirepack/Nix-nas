from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_network as firewalld  # noqa: E402
import nas_v2_network as network  # noqa: E402


class V2VlanAndDirectListenerTests(unittest.TestCase):
    def test_isolated_application_vlan_is_lowered_to_vrf_backed_podman_network(self) -> None:
        service = {
            "managed": True,
            "enabled": True,
            "runtime": {"type": "oci"},
            "workload": {"kind": "daemon"},
            "network": {
                "mode": "isolated",
                "vlanId": 42,
                "vlanParent": "eno1",
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            },
            "routes": {},
            "listeners": {},
        }
        effective = {
            "services": {"demo": service},
            "derived": {"runtime": {"demo": {"ownerUnit": "nas-v2-demo.service"}}},
        }

        reference = network.quadlet_network_reference(effective, "demo", service)
        vlan = network.vlan_binding(service["network"])
        self.assertEqual(reference, "nas-v2-net-demo.network")
        assert vlan is not None
        self.assertEqual(vlan["id"], 42)
        self.assertEqual(vlan["parent"], "eno1")

        source = (SERVICES / "nas_v2_podman_network.py").read_text(encoding="utf-8")
        self.assertIn("lines.append(f\"Options=vrf={vlan['vrfInterface']}\"", source)
        self.assertNotIn("Options=vlan=", source)
        nmstate = (SERVICES / "nas_v2_nmstate.py").read_text(encoding="utf-8")
        self.assertIn("vrfInterface", nmstate)
        self.assertIn("vlanInterface", nmstate)

    def test_vlan_is_rejected_for_host_network_mode(self) -> None:
        service = {
            "runtime": {"type": "oci"},
            "workload": {"kind": "daemon"},
            "network": {
                "mode": "host",
                "vlanId": 7,
                "vlanParent": "eno1",
                "outboundDefault": "allow",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            },
            "routes": {},
            "listeners": {},
        }
        with self.assertRaisesRegex(network.PodmanNetworkProjectionError, "host-network"):
            network.quadlet_network_reference({"services": {"demo": service}}, "demo", service)

    def test_host_listener_can_forward_privileged_port_to_unprivileged_backend(self) -> None:
        effective = {
            "services": {
                "tftp": {
                    "enabled": True,
                    "managed": False,
                    "runtime": {"type": "systemd"},
                    "network": {
                        "mode": "host",
                        "outboundDefault": "allow",
                        "lanAccess": False,
                        "allowedHostPorts": [],
                        "allowedEgress": [],
                    },
                    "listeners": {
                        "request": {
                            "protocol": "udp",
                            "exposure": {"port": 69},
                            "targetPort": 3969,
                            "firewall": True,
                        },
                        "responses": {
                            "protocol": "udp",
                            "exposure": {"start": 40000, "end": 40099},
                            "firewall": True,
                        },
                    },
                }
            }
        }
        files, _manifest = firewalld.compile_projection(effective, lan_zone="nas-trusted")
        policy = files[f"policies/{firewalld.listener_policy_name('tftp')}.xml"].decode()
        self.assertIn('forward-port port="69" protocol="udp" to-port="3969"', policy)
        self.assertIn('port="40000-40099" protocol="udp"', policy)

    def test_application_listener_rules_are_not_hard_coded_in_host_firewall_baseline(self) -> None:
        firewall_module = (ROOT / "modules" / "nas" / "config" / "network-firewall.nix").read_text(encoding="utf-8")
        native_seed = (ROOT / "modules" / "nas" / "config" / "managed-services-seed-v2.nix").read_text(encoding="utf-8")

        self.assertNotIn("cfg.tftp", firewall_module)
        self.assertNotIn('port = "22000"', firewall_module)
        self.assertNotIn('port = "3493"', firewall_module)
        self.assertIn("targetPort = cfg.tftp.internalPort", native_seed)
        self.assertIn("responsePortStart", native_seed)
        self.assertIn('sync-tcp = portListener "tcp" syncthingSyncPort', native_seed)
        self.assertIn('listeners.nut = portListener "tcp" nutUpsdPort', native_seed)

    def test_no_parallel_direct_listener_seed_remains(self) -> None:
        self.assertFalse((ROOT / "modules" / "nas" / "config" / "managed-services-direct-listeners.nix").exists())


if __name__ == "__main__":
    unittest.main()
