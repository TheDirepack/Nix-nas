from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_apply as apply_mod  # noqa: E402
import nas_v2_network as firewalld  # noqa: E402
from nas_v2_network import requires_firewalld  # noqa: E402
from nas_v2_systemd_native import SystemdProjectionError  # noqa: E402


class V2FirewalldTests(unittest.TestCase):
    def effective(self) -> dict:
        return {
            "schemaVersion": 3,
            "services": {
                "worker": {
                    "managed": True,
                    "runtime": {"type": "oci"},
                    "network": {
                        "mode": "isolated",
                        "outboundDefault": "deny",
                        "lanAccess": False,
                        "allowedHostPorts": [8080],
                        "allowedEgress": [
                            {"cidr": "203.0.113.0/24", "ports": [443]},
                            {"cidr": "2001:db8::/32", "ports": []},
                        ],
                    },
                }
            },
        }

    def test_generates_stable_zone_and_directional_policies(self):
        effective = self.effective()
        files, manifest = firewalld.compile_projection(effective, lan_zone="nas-trusted")
        self.assertTrue(requires_firewalld(effective))
        names = {value["name"] for value in files.values()}
        self.assertTrue(all(len(name) <= 17 for name in names))
        self.assertIn(f"zones/{firewalld.zone_name('worker')}", files)
        host = files[f"policies/{firewalld.host_policy_name('worker')}"]
        self.assertEqual(host["egress"], "HOST")
        self.assertIn(["8080", "tcp"], host["ports"])
        self.assertIn(["8080", "udp"], host["ports"])
        lan = files[f"policies/{firewalld.lan_policy_name('worker')}"]
        self.assertEqual((lan["target"], lan["egress"]), ("DROP", "nas-trusted"))
        world = files[f"policies/{firewalld.world_policy_name('worker')}"]
        self.assertEqual(world["target"], "DROP")
        self.assertIn({"family": "ipv4", "destination": "203.0.113.0/24", "port": "443", "protocol": "tcp"}, world["richRules"])
        self.assertIn({"family": "ipv4", "destination": "203.0.113.0/24", "port": "443", "protocol": "udp"}, world["richRules"])
        self.assertIn({"family": "ipv6", "destination": "2001:db8::/32"}, world["richRules"])
        self.assertEqual(manifest["schemaVersion"], 2)
        self.assertEqual(len(manifest["objects"]), 5)
        remote = files[f"policies/{firewalld.remote_admin_policy_name()}"]
        self.assertEqual(remote["priority"], -300)
        self.assertIn(["22", "tcp"], remote["ports"])
        self.assertIn(["9092", "tcp"], remote["ports"])
        self.assertNotIn(["9090", "tcp"], remote["ports"])

    def test_remote_admin_is_explicit_port_allowlist(self):
        files, _ = firewalld.compile_projection(self.effective(), lan_zone="nas-trusted")
        remote = files[f"policies/{firewalld.remote_admin_policy_name()}"]
        self.assertEqual((remote["target"], remote["ingress"], remote["egress"]), ("CONTINUE", "nas-trusted", "HOST"))
        self.assertIn(["22", "tcp"], remote["ports"])
        self.assertIn(["443", "tcp"], remote["ports"])

    def test_world_policy_uses_valid_nonzero_priority(self):
        files, _ = firewalld.compile_projection(self.effective(), lan_zone="nas-trusted")
        world = files[f"policies/{firewalld.world_policy_name('worker')}"]
        self.assertEqual(world["priority"], 50)

    def test_no_generated_policy_uses_reserved_priority_zero(self):
        files, _ = firewalld.compile_projection(self.effective(), lan_zone="nas-trusted")
        for target, obj in files.items():
            if obj["kind"] == "policy":
                self.assertNotEqual(obj["priority"], 0, target)

    def test_outbound_allow_and_deny_with_exceptions_validate(self):
        import copy

        for outbound in ("allow", "deny"):
            effective = copy.deepcopy(self.effective())
            effective["services"]["worker"]["network"]["outboundDefault"] = outbound
            files, _ = firewalld.compile_projection(effective, lan_zone="nas-trusted")
            world = files[f"policies/{firewalld.world_policy_name('worker')}"]
            self.assertEqual(world["target"], "ACCEPT" if outbound == "allow" else "DROP")
            self.assertEqual(world["priority"], 50)
            self.assertTrue(any(rule["destination"] == "203.0.113.0/24" for rule in world["richRules"]))
            self.assertTrue(any(rule["family"] == "ipv6" for rule in world["richRules"]))

    def test_disabled_host_listener_projects_no_firewall_opening(self):
        effective = self.effective()
        service = effective["services"]["worker"]
        service["enabled"] = False
        service["network"] = {
            "mode": "host",
            "outboundDefault": "allow",
            "lanAccess": False,
            "allowedHostPorts": [],
            "allowedEgress": [],
        }
        service["listeners"] = {
            "web": {"protocol": "tcp", "exposure": {"port": 8080}, "firewall": True},
        }
        files, manifest = firewalld.compile_projection(effective, lan_zone="trusted")
        self.assertFalse(requires_firewalld(effective))
        # Remote admin is global and remains even when no service requires firewalld
        self.assertEqual(set(files), {f"policies/{firewalld.remote_admin_policy_name()}"})
        self.assertEqual(len(manifest["objects"]), 1)
        self.assertEqual(
            manifest["owners"],
            [{"service": "_remote-admin", "target": f"policies/{firewalld.remote_admin_policy_name()}"}],
        )

    def test_unmanaged_host_listener_still_projects_declared_network_policy(self):
        effective = {
            "schemaVersion": 3,
            "services": {
                "platform": {
                    "managed": False,
                    "enabled": True,
                    "runtime": {"type": "systemd", "unit": "platform.service"},
                    "network": {
                        "mode": "host",
                        "outboundDefault": "allow",
                        "lanAccess": False,
                        "allowedHostPorts": [],
                        "allowedEgress": [],
                    },
                    "listeners": {
                        "native": {"protocol": "tcp", "exposure": {"port": 3493}, "firewall": True},
                    },
                }
            },
        }
        self.assertTrue(requires_firewalld(effective))
        files, manifest = firewalld.compile_projection(effective, lan_zone="trusted")
        policy = files[f"policies/{firewalld.listener_policy_name('platform')}"]
        self.assertEqual(policy["ingress"], "trusted")
        self.assertEqual(policy["egress"], "HOST")
        self.assertIn(["3493", "tcp"], policy["ports"])
        self.assertEqual(
            sorted(manifest["owners"], key=lambda x: x["target"]),
            sorted(
                [
                    {"service": "_remote-admin", "target": f"policies/{firewalld.remote_admin_policy_name()}"},
                    {"service": "platform", "target": f"policies/{firewalld.listener_policy_name('platform')}"},
                ],
                key=lambda x: x["target"],
            ),
        )

    def test_host_listener_can_forward_to_unprivileged_target_port(self):
        effective = {
            "schemaVersion": 3,
            "services": {
                "tftp": {
                    "managed": True,
                    "enabled": True,
                    "runtime": {"type": "systemd", "unit": "copyparty.service"},
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
                        "response": {
                            "protocol": "udp",
                            "exposure": {"start": 40000, "end": 40099},
                            "firewall": True,
                        },
                    },
                }
            },
        }
        files, _ = firewalld.compile_projection(effective, lan_zone="trusted")
        policy = files[f"policies/{firewalld.listener_policy_name('tftp')}"]
        self.assertIn(["69", "udp", "3969"], policy["forwardPorts"])
        self.assertIn(["40000-40099", "udp"], policy["ports"])
        self.assertNotIn(["69", "udp"], policy["ports"])

    def test_listener_target_port_requires_single_port_exposure(self):
        effective = {
            "schemaVersion": 3,
            "services": {
                "bad": {
                    "managed": True,
                    "runtime": {"type": "systemd", "unit": "bad.service"},
                    "network": {
                        "mode": "host",
                        "outboundDefault": "allow",
                        "lanAccess": False,
                        "allowedHostPorts": [],
                        "allowedEgress": [],
                    },
                    "listeners": {
                        "bad": {
                            "protocol": "udp",
                            "exposure": {"start": 1000, "end": 1001},
                            "targetPort": 2000,
                            "firewall": True,
                        }
                    },
                }
            },
        }
        with self.assertRaisesRegex(firewalld.FirewalldProjectionError, "single exposed port"):
            firewalld.compile_projection(effective, lan_zone="trusted")

    def test_unmanaged_isolated_network_fails_closed(self):
        effective = self.effective()
        effective["services"]["worker"]["managed"] = False
        with self.assertRaisesRegex(firewalld.FirewalldProjectionError, "no V2-owned bridge"):
            firewalld.compile_projection(effective, lan_zone="trusted")

    def test_lan_and_default_egress_allow_are_explicit(self):
        effective = self.effective()
        policy = effective["services"]["worker"]["network"]
        policy["lanAccess"] = True
        policy["outboundDefault"] = "allow"
        files, _ = firewalld.compile_projection(effective, lan_zone="trusted")
        lan = files[f"policies/{firewalld.lan_policy_name('worker')}"]
        world = files[f"policies/{firewalld.world_policy_name('worker')}"]
        self.assertEqual(lan["target"], "ACCEPT")
        self.assertEqual(world["target"], "ACCEPT")

    def test_invalid_cidr_fails_closed(self):
        effective = self.effective()
        effective["services"]["worker"]["network"]["allowedEgress"] = [{"cidr": "not-a-network", "ports": []}]
        with self.assertRaisesRegex(firewalld.FirewalldProjectionError, "invalid allowedEgress CIDR"):
            firewalld.compile_projection(effective, lan_zone="trusted")

    def test_isolated_non_container_runtime_fails_closed(self):
        effective = self.effective()
        effective["services"]["worker"]["runtime"] = {"type": "systemd"}
        with self.assertRaisesRegex(firewalld.FirewalldProjectionError, "stable V2 bridge"):
            firewalld.compile_projection(effective, lan_zone="trusted")

    def test_native_manifest_replaces_xml_artifacts(self):
        import json

        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            files = firewalld.materialize_projection(
                self.effective(), output_dir=root, lan_zone="trusted",
            )
            self.assertEqual([path.name for path, _payload, _mode in files], ["manifest.json"])
            payload = json.loads(files[0][1])
            self.assertEqual(payload["schemaVersion"], 2)
            self.assertEqual(len(payload["objects"]), 5)
            self.assertTrue(all(obj["kind"] in {"zone", "policy"} for obj in payload["objects"]))

    def test_apply_requires_firewalld_projection_for_rich_isolation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            paths = apply_mod.ApplyPaths(
                desired=root / "services.yaml",
                schema=root / "schema.json",
                platform=None,
                effective=root / "effective.json",
                plan=root / "plan.json",
            )
            original = apply_mod.compile_paths
            original_inner = getattr(apply_mod, "_compile_paths_inner", None)
            apply_mod.compile_paths = lambda _paths: (self.effective(), {"schemaVersion": 1})
            if original_inner is not None:
                apply_mod._compile_paths_inner = lambda _paths: (self.effective(), {"schemaVersion": 1})  # type: ignore[attr-defined]
            try:
                with self.assertRaisesRegex(SystemdProjectionError, "no firewalld projection"):
                    apply_mod.apply(paths)
            finally:
                apply_mod.compile_paths = original
                if original_inner is not None:
                    apply_mod._compile_paths_inner = original_inner  # type: ignore[attr-defined]

    def test_isolated_listener_target_port_fails_closed(self):
        effective = {
            "schemaVersion": 3,
            "services": {
                "isolated": {
                    "managed": True,
                    "enabled": True,
                    "runtime": {"type": "oci"},
                    "network": {
                        "mode": "isolated",
                        "outboundDefault": "deny",
                        "lanAccess": False,
                        "allowedHostPorts": [],
                        "allowedEgress": [],
                    },
                    "listeners": {
                        "web": {
                            "protocol": "tcp",
                            "exposure": {"port": 8080},
                            "targetPort": 18080,
                            "firewall": True,
                        },
                    },
                }
            },
        }
        with self.assertRaisesRegex(firewalld.FirewalldProjectionError, "targetPort"):
            firewalld.compile_projection(effective, lan_zone="trusted")

    def test_isolated_listener_and_route_policies_use_drop(self):
        effective = {
            "schemaVersion": 3,
            "services": {
                "demo": {
                    "managed": True,
                    "enabled": True,
                    "runtime": {"type": "oci"},
                    "network": {
                        "mode": "isolated",
                        "outboundDefault": "deny",
                        "lanAccess": False,
                        "allowedHostPorts": [],
                        "allowedEgress": [],
                    },
                    "listeners": {
                        "web": {"protocol": "tcp", "exposure": {"port": 8080}, "firewall": True},
                    },
                    "routes": {
                        "web": {
                            "target": {"type": "http", "host": "127.0.0.1", "port": 8081},
                            "exposure": {"type": "path", "paths": ["/"]},
                            "auth": {"mode": "public"},
                        }
                    },
                }
            },
        }
        files, _ = firewalld.compile_projection(effective, lan_zone="trusted")
        listener = files[f"policies/{firewalld.listener_policy_name('demo')}"]
        route = files[f"policies/{firewalld.route_policy_name('demo')}"]
        self.assertEqual(listener["target"], "DROP")
        self.assertNotEqual(listener["target"], "CONTINUE")
        self.assertEqual(route["target"], "DROP")
        self.assertNotEqual(route["target"], "CONTINUE")


if __name__ == "__main__":
    unittest.main()
