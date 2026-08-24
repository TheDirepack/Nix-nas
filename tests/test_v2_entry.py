from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_entry  # noqa: E402


class V2EntryTests(unittest.TestCase):
    def test_default_authority_is_canonical_services_yaml(self) -> None:
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch.object(sys, "argv", ["nas_v2_entry.py"]),
            mock.patch.object(nas_v2_entry, "apply") as apply_mock,
        ):
            self.assertEqual(nas_v2_entry.main(), 0)

        paths = apply_mock.call_args.args[0]
        self.assertEqual(paths.desired, pathlib.Path("/var/lib/nas-control/services.yaml"))

    def test_disabled_firewalld_does_not_project_policy_when_runtime_parent_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = pathlib.Path(temporary)
            env = {
                "NAS_V2_FIREWALLD": str(runtime / "firewalld"),
                "NAS_V2_FIREWALLD_ENABLED": "0",
            }
            with (
                mock.patch.dict("os.environ", env, clear=True),
                mock.patch.object(sys, "argv", ["nas_v2_entry.py"]),
                mock.patch.object(nas_v2_entry, "apply") as apply_mock,
            ):
                self.assertEqual(nas_v2_entry.main(), 0)

            self.assertIsNone(apply_mock.call_args.kwargs["firewalld"])

    def test_enabled_firewalld_projects_policy_without_preexisting_runtime_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = pathlib.Path(temporary) / "missing-parent" / "firewalld"
            env = {
                "NAS_V2_FIREWALLD": str(runtime),
                "NAS_V2_FIREWALLD_ENABLED": "1",
            }
            with (
                mock.patch.dict("os.environ", env, clear=True),
                mock.patch.object(sys, "argv", ["nas_v2_entry.py"]),
                mock.patch.object(nas_v2_entry, "apply") as apply_mock,
            ):
                self.assertEqual(nas_v2_entry.main(), 0)

            projection = apply_mock.call_args.kwargs["firewalld"]
            self.assertIsNotNone(projection)
            self.assertEqual(projection.output_dir, runtime)

    def test_network_projection_uses_nix_pinned_platform_tools(self) -> None:
        env = {
            "NAS_V2_NMCLI_BIN": "/nix/store/test-networkmanager/bin/nmcli",
            "NAS_V2_INSTALL_BIN": "/nix/store/test-coreutils/bin/install",
            "NAS_V2_RM_BIN": "/nix/store/test-coreutils/bin/rm",
            "NAS_V2_VLAN_PARENT": "enp1s0",
        }
        with (
            mock.patch.dict("os.environ", env, clear=True),
            mock.patch.object(sys, "argv", ["nas_v2_entry.py"]),
            mock.patch.object(nas_v2_entry, "apply") as apply_mock,
        ):
            self.assertEqual(nas_v2_entry.main(), 0)

        projection = apply_mock.call_args.kwargs["systemd"]
        self.assertEqual(projection.nmcli_bin, env["NAS_V2_NMCLI_BIN"])
        self.assertEqual(projection.install_bin, env["NAS_V2_INSTALL_BIN"])
        self.assertEqual(projection.rm_bin, env["NAS_V2_RM_BIN"])
        self.assertEqual(projection.vlan_parent, "enp1s0")


if __name__ == "__main__":
    unittest.main()
