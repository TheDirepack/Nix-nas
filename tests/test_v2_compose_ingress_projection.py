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
import nas_v2_network as podman_network  # noqa: E402
import nas_v2_spec as spec  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
