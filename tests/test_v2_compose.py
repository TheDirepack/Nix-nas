from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_compose as compose  # noqa: E402


class V2ComposeTests(unittest.TestCase):
    def fixture(self, root: pathlib.Path) -> tuple[dict, dict]:
        app_root = root / "apps"
        service_root = app_root / "demo"
        service_root.mkdir(parents=True)
        source = service_root / "compose.yaml"
        source.write_text(
            """services:
  web:
    image: example/web:latest
  worker:
    image: example/worker:latest
""",
            encoding="utf-8",
        )
        effective = {
            "storageResources": {"data": {"path": "/tank/data"}},
            "credentials": {
                "token": {"path": "/run/nas-secrets/token", "required": True},
                "env": {"path": "/run/nas-secrets/app.env", "required": True},
            },
            "networkProfiles": {},
        }
        service = {
            "name": "Demo",
            "managed": True,
            "enabled": True,
            "workload": {"kind": "daemon", "activation": "persistent"},
            "runtime": {"type": "compose", "source": str(source)},
            "resources": {"accelerators": []},
            "sandbox": {"mode": "inherit"},
            "storage": [],
            "credentials": [],
            "routes": [],
            "listeners": {},
        }
        return effective, service

    def render(self, effective: dict, service: dict, app_root: pathlib.Path) -> tuple[pathlib.Path, dict]:
        with mock.patch.object(compose, "APP_ROOT", app_root):
            source, rendered = compose.render_compose_override(effective, "demo", service)
        return source, json.loads(rendered)

    def test_renders_storage_file_env_and_explicit_device_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            service["storage"] = [{"resource": "data", "mountPath": "/data", "access": "write", "target": "web"}]
            service["credentials"] = [
                {"credential": "token", "use": "file", "mountPath": "/run/token", "target": "web"},
                {"credential": "env", "use": "environment-file", "target": "worker"},
            ]
            service["resources"]["accelerators"] = [
                {
                    "kind": "gpu",
                    "vendor": "AMD",
                    "quantity": 1,
                    "required": True,
                    "mode": "shared",
                    "device": "/dev/dri/renderD128",
                    "target": "worker",
                }
            ]

            source, override = self.render(effective, service, root / "apps")

            self.assertEqual(source, (root / "apps/demo/compose.yaml").resolve())
            self.assertEqual(
                override["services"]["web"]["volumes"],
                [
                    {
                        "bind": {"create_host_path": False},
                        "read_only": False,
                        "source": "/tank/data",
                        "target": "/data",
                        "type": "bind",
                    },
                    {
                        "bind": {"create_host_path": False},
                        "read_only": True,
                        "source": "/run/nas-secrets/token",
                        "target": "/run/token",
                        "type": "bind",
                    },
                ],
            )
            self.assertEqual(override["services"]["worker"]["env_file"], ["/run/nas-secrets/app.env"])
            self.assertEqual(override["services"]["worker"]["devices"], ["/dev/dri/renderD128"])

    def test_attachment_target_must_exist_in_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            service["storage"] = [{"resource": "data", "mountPath": "/data", "access": "read", "target": "missing"}]
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "does not exist"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_source_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            outside = root / "outside.yaml"
            outside.write_text("services: {web: {image: test}}\n", encoding="utf-8")
            source = pathlib.Path(service["runtime"]["source"])
            source.unlink()
            source.symlink_to(outside)
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "managed app root"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_scalar_resources_are_applied_to_each_compose_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            service["resources"]["memoryMaxBytes"] = 1024

            _source, override = self.render(effective, service, root / "apps")

            self.assertEqual(override["services"]["web"]["mem_limit"], "1024")
            self.assertEqual(override["services"]["worker"]["mem_limit"], "1024")

    def test_optional_and_native_reference_credentials_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            effective["credentials"]["token"]["required"] = False
            service["credentials"] = [
                {"credential": "token", "use": "file", "mountPath": "/run/token", "target": "web"}
            ]
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "optional Compose credential"),
            ):
                compose.render_compose_override(effective, "demo", service)

            effective["credentials"]["token"]["required"] = True
            service["credentials"][0]["use"] = "native-reference"
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "not implemented"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_network_none_applies_to_every_compose_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            service["network"] = {
                "mode": "none",
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            }

            _source, override = self.render(effective, service, root / "apps")
            self.assertEqual(override["services"]["web"]["network_mode"], "none")
            self.assertEqual(override["services"]["worker"]["network_mode"], "none")

    def test_isolated_network_uses_v2_external_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            service["network"] = {
                "mode": "isolated",
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            }

            _source, override = self.render(effective, service, root / "apps")

            self.assertEqual(override["services"]["web"]["networks"], ["nas_v2"])
            self.assertEqual(override["services"]["worker"]["networks"], ["nas_v2"])
            self.assertEqual(
                override["networks"]["nas_v2"],
                {"external": True, "name": "nas-v2-demo"},
            )


if __name__ == "__main__":
    unittest.main()
