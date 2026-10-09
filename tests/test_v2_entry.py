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

    def test_systemd_projection_keeps_only_the_host_vlan_binding(self) -> None:
        env = {"NAS_V2_VLAN_PARENT": "enp1s0"}
        with (
            mock.patch.dict("os.environ", env, clear=True),
            mock.patch.object(sys, "argv", ["nas_v2_entry.py"]),
            mock.patch.object(nas_v2_entry, "apply") as apply_mock,
        ):
            self.assertEqual(nas_v2_entry.main(), 0)

        projection = apply_mock.call_args.kwargs["systemd"]
        self.assertEqual(projection.vlan_parent, "enp1s0")
        self.assertFalse(hasattr(projection, "nmcli_bin"))
        self.assertFalse(hasattr(projection, "install_bin"))
        self.assertFalse(hasattr(projection, "rm_bin"))

    def test_explicit_options_override_environment_without_mutating_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = root / "services.yaml"
            schema = root / "schema.json"
            effective = root / "effective.json"
            env = {
                "NAS_V2_PLATFORM": str(root / "host-platform.json"),
                "NAS_V2_DESIRED": "/unexpected/services.yaml",
            }
            with (
                mock.patch.dict("os.environ", env, clear=True),
                mock.patch.object(sys, "argv", ["nas_v2_entry.py", "/unexpected/argv.yaml"]),
                mock.patch.object(nas_v2_entry, "apply") as apply_mock,
            ):
                before = dict(__import__("os").environ)
                status = nas_v2_entry.main(overrides={
                    "NAS_V2_DESIRED": str(spec),
                    "NAS_V2_SCHEMA": str(schema),
                    "NAS_V2_EFFECTIVE": str(effective),
                    "NAS_V2_PLATFORM": None,
                    "NAS_V2_HISTORY_REPOSITORY": None,
                })
                self.assertEqual(dict(__import__("os").environ), before)
            self.assertEqual(status, 0)
            paths = apply_mock.call_args.args[0]
            self.assertEqual(paths.desired, spec)
            self.assertEqual(paths.schema, schema)
            self.assertEqual(paths.effective, effective)
            self.assertIsNone(paths.platform)
            self.assertIsNone(paths.history_repository)


if __name__ == "__main__":
    unittest.main()
