from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_managed_network as network  # noqa: E402


class ManagedNetworkTests(unittest.TestCase):
    def test_service_network_is_stable_and_isolated(self) -> None:
        first = network.service_network("demo")
        second = network.service_network("demo")
        other = network.service_network("other")
        self.assertEqual(first, second)
        self.assertNotEqual(first["subnet"], other["subnet"])
        self.assertTrue(first["quadlet"].endswith(".network"))
        self.assertLessEqual(len(first["worldPolicy"]), 17)
        self.assertLessEqual(len(first["hostPolicy"]), 17)

    def test_normalize_network_policy_fails_closed(self) -> None:
        normalized = network.normalize_network_policy(
            {
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedEgress": [{"cidr": "1.1.1.1/32", "ports": [443, 443]}],
                "allowedHostPorts": [9292],
            }
        )
        self.assertEqual(normalized["allowedEgress"][0]["cidr"], "1.1.1.1/32")
        self.assertEqual(normalized["allowedEgress"][0]["ports"], [443])
        self.assertEqual(normalized["allowedHostPorts"], [9292])
        for bad in (
            {"outboundDefault": "maybe"},
            {"lanAccess": "no"},
            {"allowedHostPorts": [0]},
            {"allowedEgress": [{"cidr": "not-a-cidr"}]},
            {"unknown": True},
        ):
            with self.subTest(bad=bad), self.assertRaises(Exception):
                network.normalize_network_policy(bad)

    def test_merge_network_policy_overrides_named_profile(self) -> None:
        merged = network.merge_network_policy(
            {"outboundDefault": "allow", "lanAccess": False},
            {"outboundDefault": "deny", "allowedHostPorts": [9292]},
        )
        self.assertEqual(merged["outboundDefault"], "deny")
        self.assertFalse(merged["lanAccess"])
        self.assertEqual(merged["allowedHostPorts"], [9292])

    def test_quadlet_network_is_native_and_deterministic(self) -> None:
        rendered = network.render_network_quadlet("demo")
        definition = network.service_network("demo")
        self.assertIn("[Network]", rendered)
        self.assertIn(f"NetworkName={definition['networkName']}", rendered)
        self.assertIn(f"Subnet={definition['subnet']}", rendered)
        self.assertIn("Options=isolate=true", rendered)

    def test_firewalld_plan_denies_lan_and_limits_host(self) -> None:
        plan = network.firewalld_plan(
            "pi",
            {
                "outboundDefault": "allow",
                "lanAccess": False,
                "allowedHostPorts": [9292],
            },
        )
        self.assertEqual(plan["worldTarget"], "ACCEPT")
        self.assertIn(9292, plan["hostPorts"])
        self.assertIn(53, plan["hostPorts"])
        joined = "\n".join(plan["worldRules"])
        self.assertIn("192.168.0.0/16", joined)
        self.assertIn("172.16.0.0/12", joined)

    @mock.patch.object(network.subprocess, "run")
    def test_apply_dry_run_has_no_side_effects(self, run) -> None:
        plan = network.apply_firewalld("demo", {"outboundDefault": "deny"}, dry_run=True)
        self.assertEqual(plan["worldTarget"], "REJECT")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
