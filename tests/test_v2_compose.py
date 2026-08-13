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
            "routes": {},
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

    def test_isolated_ingress_is_published_on_selected_compose_services(self):
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
            service["listeners"] = {
                "api": {
                    "protocol": "tcp",
                    "exposure": {"port": 18080},
                    "targetPort": 8080,
                    "runtimeTarget": "web",
                    "firewall": True,
                },
                "discovery": {
                    "protocol": "udp",
                    "exposure": {"start": 19000, "end": 19002},
                    "runtimeTarget": "worker",
                    "firewall": True,
                },
            }
            service["routes"] = {
                "ui": {
                    "runtimeTarget": "web",
                    "target": {"type": "http", "host": "127.0.0.1", "port": 8081},
                    "exposure": {"type": "path", "paths": ["/demo"]},
                    "auth": {"mode": "public"},
                }
            }

            _source, override = self.render(effective, service, root / "apps")

            self.assertEqual(
                override["services"]["web"]["ports"],
                ["18080:8080/tcp", "127.0.0.1:8081:8081/tcp"],
            )
            self.assertEqual(override["services"]["worker"]["ports"], ["19000-19002:19000-19002/udp"])

    def test_isolated_ingress_requires_existing_runtime_target(self):
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
            service["listeners"] = {
                "api": {
                    "protocol": "tcp",
                    "exposure": {"port": 18080},
                    "runtimeTarget": "missing",
                    "firewall": True,
                }
            }

            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "runtimeTarget 'missing' does not exist"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_isolated_route_rejects_non_loopback_target(self):
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
            service["routes"] = {
                "ui": {
                    "runtimeTarget": "web",
                    "target": {"type": "http", "host": "0.0.0.0", "port": 8081},
                    "exposure": {"type": "path", "paths": ["/demo"]},
                    "auth": {"mode": "public"},
                }
            }

            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "must use a loopback host target"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_strict_rejects_host_bind_mount_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            source = pathlib.Path(service["runtime"]["source"])
            source.write_text(
                "services:\n  web:\n    image: example/web:latest\n    volumes:\n      - /:/host:rw\n  worker:\n    image: example/worker:latest\n",
                encoding="utf-8",
            )
            service["sandbox"] = {"mode": "strict"}
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "host volume"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_strict_rejects_host_bind_mount_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            source = pathlib.Path(service["runtime"]["source"])
            source.write_text(
                "services:\n  web:\n    image: example/web:latest\n    volumes:\n      - type: bind\n        source: /etc/shadow\n        target: /shadow\n  worker:\n    image: example/worker:latest\n",
                encoding="utf-8",
            )
            service["sandbox"] = {"mode": "strict"}
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "host volume"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_strict_rejects_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            source = pathlib.Path(service["runtime"]["source"])
            source.write_text(
                "services:\n  web:\n    image: example/web:latest\n    env_file: /etc/shadow\n  worker:\n    image: example/worker:latest\n",
                encoding="utf-8",
            )
            service["sandbox"] = {"mode": "strict"}
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "env_file"),
            ):
                compose.render_compose_override(effective, "demo", service)
            source.write_text(
                "services:\n  web:\n    image: example/web:latest\n    env_file:\n      - /etc/shadow\n  worker:\n    image: example/worker:latest\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "env_file"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_strict_allows_non_host_volume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            source = pathlib.Path(service["runtime"]["source"])
            source.write_text(
                "services:\n  web:\n    image: example/web:latest\n    volumes:\n      - data:/data\n  worker:\n    image: example/worker:latest\n",
                encoding="utf-8",
            )
            service["sandbox"] = {"mode": "strict"}
            _source, override = self.render(effective, service, root / "apps")
            self.assertIn("web", override["services"])

    def test_isolated_listener_range_not_duplicated_when_all_ports_already_published(self):
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
            service["listeners"] = {
                "a": {
                    "protocol": "udp",
                    "exposure": {"start": 19000, "end": 19002},
                    "runtimeTarget": "web",
                    "firewall": True,
                },
                "b": {
                    "protocol": "udp",
                    "exposure": {"start": 19000, "end": 19002},
                    "runtimeTarget": "web",
                    "firewall": True,
                },
            }
            _source, override = self.render(effective, service, root / "apps")
            ports = override["services"]["web"]["ports"]
            self.assertEqual(ports.count("19000-19002:19000-19002/udp"), 1)
            self.assertEqual(len(ports), 1)

    def test_isolated_listener_range_appended_when_some_port_new(self):
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
            service["listeners"] = {
                "a": {
                    "protocol": "tcp",
                    "exposure": {"port": 19000},
                    "runtimeTarget": "web",
                    "firewall": True,
                },
                "b": {
                    "protocol": "tcp",
                    "exposure": {"start": 19000, "end": 19001},
                    "runtimeTarget": "web",
                    "firewall": True,
                },
            }
            _source, override = self.render(effective, service, root / "apps")
            ports = override["services"]["web"]["ports"]
            self.assertIn("19000:19000/tcp", ports)
            self.assertIn("19000-19001:19000-19001/tcp", ports)

    def test_tmpfs_requires_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            service["sandbox"] = {"mode": "strict", "tmpfs": [{"path": "relative/path"}]}
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "absolute path"),
            ):
                compose.render_compose_override(effective, "demo", service)
            service["sandbox"] = {"mode": "strict", "tmpfs": [{"path": "/tmp/../escape"}]}
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, r"\.\."),
            ):
                compose.render_compose_override(effective, "demo", service)
            service["sandbox"] = {"mode": "strict", "tmpfs": [{"path": "/cache", "sizeBytes": 1024}]}
            _source, override = self.render(effective, service, root / "apps")
            self.assertEqual(override["services"]["web"]["volumes"][0]["target"], "/cache")

    def test_duplicate_mount_targets_via_storage_and_tmpfs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            service["sandbox"] = {"mode": "strict", "tmpfs": [{"path": "/data"}]}
            service["storage"] = [{"resource": "data", "mountPath": "/data", "access": "write", "target": "web"}]
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "duplicate mount target"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_duplicate_mount_targets_via_storage_and_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            service["storage"] = [{"resource": "data", "mountPath": "/shared", "access": "write", "target": "web"}]
            service["credentials"] = [{"credential": "token", "use": "file", "mountPath": "/shared", "target": "web"}]
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "duplicate mount target"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_duplicate_mount_targets_app_vs_v2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            source = pathlib.Path(service["runtime"]["source"])
            source.write_text(
                "services:\n  web:\n    image: example/web:latest\n    volumes:\n      - data:/data\n  worker:\n    image: example/worker:latest\n",
                encoding="utf-8",
            )
            service["storage"] = [{"resource": "data", "mountPath": "/data", "access": "write", "target": "web"}]
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "duplicate mount target"),
            ):
                compose.render_compose_override(effective, "demo", service)

    def test_duplicate_mount_targets_within_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            effective, service = self.fixture(root)
            source = pathlib.Path(service["runtime"]["source"])
            source.write_text(
                "services:\n  web:\n    image: example/web:latest\n    volumes:\n      - data:/data\n      - other:/data\n  worker:\n    image: example/worker:latest\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(compose, "APP_ROOT", root / "apps"),
                self.assertRaisesRegex(compose.ComposeProjectionError, "duplicate mount target"),
            ):
                compose.render_compose_override(effective, "demo", service)


if __name__ == "__main__":
    unittest.main()
