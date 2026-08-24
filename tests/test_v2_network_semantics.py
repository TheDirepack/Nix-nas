from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_spec as v2  # noqa: E402


def service(*, runtime: dict | None = None, managed: bool = True) -> dict:
    return {
        "name": "Network semantic test",
        "managed": managed,
        "workload": {"kind": "daemon", "activation": "persistent"},
        "runtime": runtime
        or {
            "type": "oci",
            "image": "example.invalid/network-test:1",
            "pull": "missing",
            "command": [],
        },
    }


class V2NetworkSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def compile(self, document: dict) -> dict:
        return v2.compile_document(document, self.schema)

    def test_target_port_requires_single_exposed_port(self):
        candidate = service(runtime={"type": "systemd", "unit": "example.service"})
        candidate["listeners"] = {
            "range": {
                "protocol": "udp",
                "exposure": {"start": 30000, "end": 30010},
                "targetPort": 31000,
            }
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "single exposed port") as raised:
            self.compile({"schemaVersion": 3, "services": {"example": candidate}})
        self.assertEqual(raised.exception.code, "listener-target-port")

    def test_target_port_single_port_remap_is_valid(self):
        candidate = service(runtime={"type": "systemd", "unit": "example.service"})
        candidate["listeners"] = {
            "web": {
                "protocol": "tcp",
                "exposure": {"port": 8443},
                "targetPort": 9443,
            }
        }
        effective = self.compile({"schemaVersion": 3, "services": {"example": candidate}})
        self.assertEqual(effective["services"]["example"]["listeners"]["web"]["targetPort"], 9443)

    def test_isolated_network_rejects_runtime_without_stable_v2_bridge(self):
        candidate = service(runtime={"type": "exec", "command": ["/bin/true"]})
        candidate["network"] = {"mode": "isolated"}
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "stable V2 bridge") as raised:
            self.compile({"schemaVersion": 3, "services": {"example": candidate}})
        self.assertEqual(raised.exception.code, "network-isolated-runtime")

    def test_isolated_session_requires_direct_oci_runtime(self):
        candidate = service(
            runtime={
                "type": "compose",
                "source": "/var/lib/nas-control/apps/example/compose.yaml",
            }
        )
        candidate["workload"] = {"kind": "session"}
        candidate["network"] = {"mode": "isolated"}
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "direct OCI") as raised:
            self.compile({"schemaVersion": 3, "services": {"example": candidate}})
        self.assertEqual(raised.exception.code, "network-session-runtime")

    def test_vlan_requires_isolated_network_mode(self):
        candidate = service()
        candidate["network"] = {
            "mode": "host",
            "vlanId": 42,
            "outboundDefault": "allow",
            "lanAccess": False,
            "allowedHostPorts": [],
            "allowedEgress": [],
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "mode 'isolated'") as raised:
            self.compile({"schemaVersion": 3, "services": {"example": candidate}})
        self.assertEqual(raised.exception.code, "network-vlan")

    def test_vlan_requires_v2_managed_container_runtime(self):
        cases = [
            service(runtime={"type": "systemd", "unit": "example.service"}),
            service(managed=False),
        ]
        for candidate in cases:
            candidate["network"] = {
                "mode": "isolated",
                "vlanId": 42,
                "outboundDefault": "allow",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            }
            with self.subTest(runtime=candidate["runtime"]["type"], managed=candidate["managed"]):
                with self.assertRaisesRegex(v2.ManagedServicesV2Error, "V2-managed OCI, Quadlet, or Compose") as raised:
                    self.compile({"schemaVersion": 3, "services": {"example": candidate}})
                self.assertEqual(raised.exception.code, "network-vlan-runtime")

    def test_vlan_profile_requires_isolated_mode_even_when_unused(self):
        document = {
            "schemaVersion": 3,
            "networkProfiles": {
                "bad": {
                    "mode": "host",
                    "vlanId": 120,
                    "outboundDefault": "allow",
                    "lanAccess": False,
                    "allowedHostPorts": [],
                    "allowedEgress": [],
                }
            },
            "services": {},
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "mode 'isolated'") as raised:
            self.compile(document)
        self.assertEqual(raised.exception.code, "network-vlan")

    def test_valid_vlan_remains_portable_and_does_not_gain_host_parent(self):
        candidate = service()
        candidate["network"] = {
            "mode": "isolated",
            "vlanId": 42,
            "outboundDefault": "allow",
            "lanAccess": False,
            "allowedHostPorts": [],
            "allowedEgress": [],
        }
        effective = self.compile({"schemaVersion": 3, "services": {"example": candidate}})
        policy = effective["services"]["example"]["network"]
        self.assertEqual(policy["vlanId"], 42)
        self.assertNotIn("vlanParent", policy)


if __name__ == "__main__":
    unittest.main()
