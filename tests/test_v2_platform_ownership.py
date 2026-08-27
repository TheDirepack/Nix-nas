"""Consolidated platform_ownership suites (merged from 3 micro-files)."""

from __future__ import annotations

import os
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_apply as apply_v2  # noqa: E402
from nas_v2_systemd_native import SystemdProjectionError  # noqa: E402


class V2PlatformRuntimeOwnershipTests(unittest.TestCase):
    def test_libvirt_daemon_is_platform_substrate_not_application_lifecycle(self) -> None:
        seed = (ROOT / "modules/nas/config/managed-services-seed-v2.nix").read_text(encoding="utf-8")

        self.assertIn(
            'virtualization = platformService ((daemon "libvirtd.service" "libvirt virtual-machine runtime") // {',
            seed,
        )
        self.assertIn('vm-storage = (job "nas-vm-storage.service" "Prepare VM storage") // {', seed)
        self.assertIn(
            'vm-storage-pool = (daemon "nas-vm-storage-pool.service" "Activate the ZFS-backed libvirt storage pool") // {',
            seed,
        )
        self.assertNotIn('virtualization = (daemon "libvirtd.service"', seed)


class ManagedServicesV2PlatformRouteOwnershipTests(unittest.TestCase):
    def test_cockpit_console_route_is_seeded_only_through_v2(self) -> None:
        seed = (ROOT / "modules" / "nas" / "config" / "managed-services-seed-v2.nix").read_text(encoding="utf-8")
        proxy = (ROOT / "modules" / "nas" / "config" / "reverse-proxy.nix").read_text(encoding="utf-8")
        cockpit = seed.split("cockpit = {", 1)[1].split("    };\n  };", 1)[0]

        self.assertIn("platformServices", seed)
        self.assertIn('paths = [ "/console" ];', cockpit)
        self.assertIn('type = "unix-http";', cockpit)
        self.assertIn('socket = "/run/nas-cockpit-proxy/http.sock";', cockpit)
        self.assertNotIn('host = "127.0.0.1";', cockpit)
        self.assertIn('capability = "admin";', cockpit)
        self.assertIn('title = "System Console";', cockpit)

        self.assertNotIn("@console", proxy)
        self.assertNotIn("tls_insecure_skip_verify", proxy)
        self.assertNotIn("cockpitPort", proxy)


class V2VlanPlatformBindingTests(unittest.TestCase):
    def effective(self, *, profile: bool = False, enabled: bool = True) -> dict:
        policy = {
            "mode": "isolated",
            "vlanId": 42,
            "outboundDefault": "allow",
            "lanAccess": False,
            "allowedHostPorts": [],
            "allowedEgress": [],
        }
        service = {
            "enabled": enabled,
            "managed": True,
            "workload": {"kind": "daemon", "activation": "persistent"},
            "runtime": {"type": "oci", "image": "example.invalid/demo:1", "pull": "missing", "command": []},
        }
        profiles: dict[str, dict] = {}
        if profile:
            service["networkProfile"] = "media"
            profiles["media"] = policy
        else:
            service["network"] = policy
        return {"services": {"demo": service}, "networkProfiles": profiles}

    def test_direct_vlan_binds_host_parent_without_mutating_effective_state(self):
        effective = self.effective()
        bound = apply_v2._bind_platform_vlan_parent(effective, "eno1")
        self.assertIsNot(bound, effective)
        self.assertEqual(bound["services"]["demo"]["network"]["vlanParent"], "eno1")
        self.assertNotIn("vlanParent", effective["services"]["demo"]["network"])

    def test_profile_vlan_binds_host_parent_without_mutating_profile(self):
        effective = self.effective(profile=True)
        bound = apply_v2._bind_platform_vlan_parent(effective, "enp4s0")
        self.assertEqual(bound["networkProfiles"]["media"]["vlanParent"], "enp4s0")
        self.assertNotIn("vlanParent", effective["networkProfiles"]["media"])

    def test_active_vlan_fails_closed_without_host_trunk(self):
        with self.assertRaisesRegex(SystemdProjectionError, "applicationVlanParent"):
            apply_v2._bind_platform_vlan_parent(self.effective(), None)

    def test_disabled_vlan_does_not_require_host_trunk(self):
        effective = self.effective(enabled=False)
        self.assertIs(apply_v2._bind_platform_vlan_parent(effective, None), effective)

    def test_systemd_projection_reads_platform_parent_from_environment_per_instance(self):
        kwargs = {
            "output_dir": pathlib.Path("/tmp/v2"),
            "systemd_analyze_bin": "systemd-analyze",
            "python_bin": "python3",
            "source_dir": pathlib.Path("/src"),
            "systemctl_bin": "systemctl",
            "uv_bin": "uv",
        }
        with mock.patch.dict(os.environ, {"NAS_V2_VLAN_PARENT": "eno2"}, clear=False):
            projection = apply_v2.SystemdProjection(**kwargs)
        self.assertEqual(projection.vlan_parent, "eno2")
