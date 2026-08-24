"""Consolidated compose_projection suites (merged from 4 micro-files)."""

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
import nas_v2_network as firewalld  # noqa: E402
import nas_v2_network as podman_network  # noqa: E402
import nas_v2_spec as spec  # noqa: E402


class V2ComposeNetworkAuthorityTests(unittest.TestCase):
    def test_v2_network_policy_rejects_source_declared_ports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            source = app_root / "demo" / "compose.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(
                "services:\n  web:\n    image: example/web\n    ports: ['0.0.0.0:9999:9999']\n",
                encoding="utf-8",
            )
            effective = {"networkProfiles": {}, "storageResources": {}, "credentials": {}}
            service = {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "compose", "source": str(source)},
                "resources": {"accelerators": []},
                "sandbox": {"mode": "inherit"},
                "storage": [],
                "credentials": [],
                "routes": {},
                "listeners": {},
                "network": {
                    "mode": "isolated",
                    "outboundDefault": "deny",
                    "lanAccess": False,
                    "allowedHostPorts": [],
                    "allowedEgress": [],
                },
            }
            with (
                mock.patch.object(compose, "APP_ROOT", app_root),
                self.assertRaisesRegex(compose.ComposeProjectionError, "V2-owned network fields: ports"),
            ):
                compose.render_compose_override(effective, "demo", service)


class V2ComposeFirewalldTests(unittest.TestCase):
    def test_targeted_compose_ingress_uses_exposed_listener_and_route_ports(self) -> None:
        service = {
            "managed": True,
            "enabled": True,
            "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/demo/compose.yaml"},
            "workload": {"kind": "daemon", "activation": "persistent"},
            "network": {
                "mode": "isolated",
                "outboundDefault": "deny",
                "lanAccess": False,
                "allowedHostPorts": [],
                "allowedEgress": [],
            },
            "routes": {
                "web": {
                    "runtimeTarget": "web",
                    "target": {"type": "http", "host": "127.0.0.1", "port": 8081},
                    "exposure": {"type": "path", "paths": ["/demo"]},
                    "auth": {"mode": "public"},
                }
            },
            "listeners": {
                "api": {
                    "protocol": "tcp",
                    "exposure": {"port": 18080},
                    "runtimeTarget": "web",
                    "firewall": True,
                },
                "discovery": {
                    "protocol": "udp",
                    "exposure": {"start": 19000, "end": 19002},
                    "runtimeTarget": "worker",
                    "firewall": True,
                },
            },
        }
        effective = {"services": {"demo": service}, "networkProfiles": {}}

        files, _manifest = firewalld.compile_projection(effective, lan_zone="nas-trusted")
        listener = files[f"policies/{firewalld.listener_policy_name('demo')}.xml"].decode()
        route = files[f"policies/{firewalld.route_policy_name('demo')}.xml"].decode()

        self.assertIn('port="18080" protocol="tcp"', listener)
        self.assertIn('port="19000-19002" protocol="udp"', listener)
        self.assertNotIn('port="8080" protocol="tcp"', listener)
        self.assertIn('<ingress-zone name="HOST"/>', route)
        self.assertIn('port="8081" protocol="tcp"', route)


class V2ComposeIngressProjectionTests(unittest.TestCase):
    def test_compiled_targeted_ingress_reaches_compose_and_network_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            source = app_root / "multi" / "compose.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(
                "services: {web: {image: example/web}, discovery: {image: example/discovery}}\n",
                encoding="utf-8",
            )
            document = {
                "schemaVersion": 3,
                "services": {
                    "multi": {
                        "name": "Multi-container app",
                        "workload": {"kind": "daemon"},
                        "runtime": {"type": "compose", "source": str(source)},
                        "network": {
                            "mode": "isolated",
                            "outboundDefault": "deny",
                            "lanAccess": False,
                            "allowedHostPorts": [],
                            "allowedEgress": [],
                        },
                        "routes": {
                            "web": {
                                "runtimeTarget": "web",
                                "target": {"type": "http", "port": 8080},
                                "exposure": {"type": "path", "paths": ["/multi"]},
                                "auth": {"mode": "public"},
                            }
                        },
                        "listeners": {
                            "discovery": {
                                "protocol": "udp",
                                "exposure": {"port": 19000},
                                "targetPort": 9000,
                                "runtimeTarget": "discovery",
                            }
                        },
                    }
                },
            }
            schema = spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
            with mock.patch.object(spec, "APP_ROOT", pathlib.PurePosixPath(app_root)):
                effective = spec.compile_document(document, schema)
            service = effective["services"]["multi"]
            with mock.patch.object(compose, "APP_ROOT", app_root):
                _source, rendered = compose.render_compose_override(effective, "multi", service)

        override = json.loads(rendered)
        self.assertEqual(override["services"]["web"]["ports"], ["127.0.0.1:8080:8080/tcp"])
        self.assertEqual(override["services"]["discovery"]["ports"], ["19000:9000/udp"])
        self.assertEqual(
            podman_network.quadlet_network_reference(effective, "multi", service),
            "nas-v2-net-multi.network",
        )


class V2ComposeIngressSchemaTests(unittest.TestCase):
    def document(self, source: pathlib.Path) -> dict:
        return {
            "schemaVersion": 3,
            "services": {
                "demo": {
                    "name": "Demo",
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "compose", "source": str(source)},
                    "network": {
                        "mode": "isolated",
                        "outboundDefault": "deny",
                        "lanAccess": False,
                        "allowedHostPorts": [],
                        "allowedEgress": [],
                    },
                    "routes": {
                        "web": {
                            "runtimeTarget": "frontend",
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/demo"]},
                            "auth": {"mode": "public"},
                        }
                    },
                    "listeners": {
                        "discovery": {
                            "protocol": "udp",
                            "exposure": {"port": 19000},
                            "targetPort": 9000,
                            "runtimeTarget": "worker",
                        }
                    },
                }
            },
        }

    def test_runtime_targets_survive_schema_normalization_and_effective_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            source = app_root / "demo" / "compose.yaml"
            source.parent.mkdir(parents=True)
            source.write_text("services: {frontend: {image: demo}, worker: {image: worker}}\n", encoding="utf-8")
            schema = spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
            with mock.patch.object(spec, "APP_ROOT", pathlib.PurePosixPath(app_root)):
                effective = spec.compile_document(self.document(source), schema)

        service = effective["services"]["demo"]
        self.assertEqual(service["routes"]["web"]["runtimeTarget"], "frontend")
        self.assertEqual(service["listeners"]["discovery"]["runtimeTarget"], "worker")
        self.assertEqual(service["listeners"]["discovery"]["targetPort"], 9000)

    def test_runtime_target_must_be_non_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            source = app_root / "demo" / "compose.yaml"
            source.parent.mkdir(parents=True)
            source.write_text("services: {frontend: {image: demo}}\n", encoding="utf-8")
            document = self.document(source)
            document["services"]["demo"]["routes"]["web"]["runtimeTarget"] = ""
            schema = spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
            with (
                mock.patch.object(spec, "APP_ROOT", pathlib.PurePosixPath(app_root)),
                self.assertRaisesRegex(spec.ManagedServicesV2Error, "should be non-empty"),
            ):
                spec.compile_document(document, schema)
