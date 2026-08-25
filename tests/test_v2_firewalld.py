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
        names = {
            firewalld.zone_name("worker"),
            firewalld.host_policy_name("worker"),
            firewalld.lan_policy_name("worker"),
            firewalld.world_policy_name("worker"),
            firewalld.remote_admin_policy_name(),
        }
        self.assertTrue(all(len(name) <= 17 for name in names))
        host = files[f"policies/{firewalld.host_policy_name('worker')}.xml"].decode()
        self.assertIn('egress-zone name="HOST"', host)
        self.assertIn('port="8080" protocol="tcp"', host)
        self.assertIn('port="8080" protocol="udp"', host)
        lan = files[f"policies/{firewalld.lan_policy_name('worker')}.xml"].decode()
        self.assertIn('target="DROP"', lan)
        self.assertIn('egress-zone name="nas-trusted"', lan)
        world = files[f"policies/{firewalld.world_policy_name('worker')}.xml"].decode()
        self.assertIn('target="DROP"', world)
        self.assertIn('destination address="203.0.113.0/24"', world)
        self.assertIn('port="443" protocol="tcp"', world)
        self.assertIn('port="443" protocol="udp"', world)
        self.assertIn('family="ipv6"', world)
        # 4 service policies + 1 global remote admin (priority -300)
        self.assertEqual(len(manifest["files"]), 5)
        remote = files[f"policies/{firewalld.remote_admin_policy_name()}.xml"].decode()
        self.assertIn('priority="-300"', remote)
        self.assertIn("V2 remote admin", remote)
        self.assertIn('port="22"', remote)
        self.assertIn('port="9092"', remote)
        self.assertNotIn('port="9090"', remote)

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
        self.assertEqual(set(files), {f"policies/{firewalld.remote_admin_policy_name()}.xml"})
        self.assertEqual(len(manifest["files"]), 1)
        self.assertEqual(
            manifest["owners"],
            [{"service": "_remote-admin", "target": f"policies/{firewalld.remote_admin_policy_name()}.xml"}],
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
        policy = files[f"policies/{firewalld.listener_policy_name('platform')}.xml"].decode()
        self.assertIn('ingress-zone name="trusted"', policy)
        self.assertIn('egress-zone name="HOST"', policy)
        self.assertIn('port="3493" protocol="tcp"', policy)
        self.assertEqual(
            sorted(manifest["owners"], key=lambda x: x["target"]),
            sorted(
                [
                    {"service": "_remote-admin", "target": f"policies/{firewalld.remote_admin_policy_name()}.xml"},
                    {"service": "platform", "target": f"policies/{firewalld.listener_policy_name('platform')}.xml"},
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
        policy = files[f"policies/{firewalld.listener_policy_name('tftp')}.xml"].decode()
        self.assertIn('forward-port port="69" protocol="udp" to-port="3969"', policy)
        self.assertIn('port="40000-40099" protocol="udp"', policy)
        self.assertNotIn('<port port="69" protocol="udp"', policy)

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
        lan = files[f"policies/{firewalld.lan_policy_name('worker')}.xml"].decode()
        world = files[f"policies/{firewalld.world_policy_name('worker')}.xml"].decode()
        self.assertIn('target="ACCEPT"', lan)
        self.assertIn('target="ACCEPT"', world)

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

    def test_native_validator_is_invoked(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            validator = root / "firewall-offline-cmd"
            log = root / "args"
            validator.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {log}\nexit 0\n", encoding="utf-8")
            validator.chmod(validator.stat().st_mode | stat.S_IXUSR)
            files, _ = firewalld.compile_projection(self.effective(), lan_zone="trusted")
            firewalld.validate_projection(files, firewall_offline_cmd=str(validator))
            self.assertIn("--check-config", log.read_text(encoding="utf-8"))

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
        listener = files[f"policies/{firewalld.listener_policy_name('demo')}.xml"].decode()
        route = files[f"policies/{firewalld.route_policy_name('demo')}.xml"].decode()
        self.assertIn('target="DROP"', listener)
        self.assertNotIn('target="CONTINUE"', listener)
        self.assertIn('target="DROP"', route)
        self.assertNotIn('target="CONTINUE"', route)


if __name__ == "__main__":
    unittest.main()
