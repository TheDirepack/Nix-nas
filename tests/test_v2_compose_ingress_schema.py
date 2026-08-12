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

import nas_v2_spec as spec  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
