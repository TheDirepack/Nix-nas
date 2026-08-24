from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_nmstate as nmstate  # noqa: E402


def _effective() -> dict:
    return {
        "schemaVersion": 3,
        "networkProfiles": {},
        "services": {
            "demo": {
                "managed": True,
                "enabled": True,
                "workload": {"kind": "daemon"},
                "runtime": {"type": "oci"},
                "network": {
                    "mode": "isolated",
                    "outboundDefault": "allow",
                    "lanAccess": False,
                    "allowedHostPorts": [],
                    "allowedEgress": [],
                    "vlanId": 42,
                },
            }
        },
    }


class V2NmstateTests(unittest.TestCase):
    def test_desired_state_preserves_deterministic_vlan_binding(self) -> None:
        state = nmstate.desired_state(_effective(), vlan_parent="enp1s0")
        self.assertEqual(len(state["interfaces"]), 2)
        vlan, vrf = state["interfaces"]
        self.assertEqual(vlan["type"], "vlan")
        self.assertEqual(vlan["vlan"], {"base-iface": "enp1s0", "id": 42})
        self.assertTrue(vlan["name"].startswith("nv2vl"))
        self.assertEqual(vrf["type"], "vrf")
        self.assertEqual(vrf["vrf"]["port"], [vlan["name"]])
        self.assertTrue(vrf["name"].startswith("nv2vrf"))

    def test_vlan_requires_platform_parent(self) -> None:
        with self.assertRaisesRegex(nmstate.NmstateReconcileError, "applicationVlanParent"):
            nmstate.desired_state(_effective())

    def test_stale_owned_interfaces_are_explicitly_absent(self) -> None:
        desired = {"interfaces": [{"name": "nv2vl12345678", "type": "vlan", "state": "up"}]}
        current = {
            "interfaces": [
                {"name": "nv2vl12345678", "type": "vlan"},
                {"name": "nv2vl87654321", "type": "vlan"},
                {"name": "nv2vrf7654321", "type": "vrf"},
                {"name": "eth0", "type": "ethernet"},
                {"name": "nv2-not-owned", "type": "ethernet"},
            ]
        }
        merged = nmstate._with_stale_absent(desired, current)
        absent = [item for item in merged["interfaces"] if item.get("state") == "absent"]
        self.assertEqual(
            absent,
            [
                {"name": "nv2vrf7654321", "state": "absent"},
                {"name": "nv2vl87654321", "state": "absent"},
            ],
        )

    def test_reconcile_uses_nmstate_show_and_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / "nmstatectl"
            log = pathlib.Path(tmp) / "log"
            fake.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = show ]; then printf '%s\\n' '{\"interfaces\": []}'; exit 0; fi\n"
                f"cat > {log}\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            result = nmstate.reconcile(_effective(), nmstatectl=str(fake), vlan_parent="enp1s0")
            self.assertTrue(result["ok"])
            payload = json.loads(log.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["interfaces"]), 2)


if __name__ == "__main__":
    unittest.main()
