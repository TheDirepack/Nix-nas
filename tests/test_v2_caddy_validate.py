from __future__ import annotations

import os
import pathlib
import shutil
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_spec as v2  # noqa: E402


def _caddy_binary() -> str | None:
    configured = os.environ.get("CADDY_BIN")
    if configured and pathlib.Path(configured).is_file():
        return configured
    return shutil.which("caddy")


class ManagedServicesV2RealCaddyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)
        cls.caddy_bin = _caddy_binary()
        if cls.caddy_bin is None:
            raise unittest.SkipTest("caddy binary not available")

    def compile(self, services: dict) -> dict:
        return v2.compile_document({"schemaVersion": 3, "services": services}, self.schema)

    def test_empty_projection_is_accepted_by_real_caddy(self):
        effective = self.compile({})
        caddy.validate_caddyfile(caddy.generate_caddyfile(effective), caddy_bin=self.caddy_bin)

    def test_identity_and_public_routes_are_accepted_by_real_caddy(self):
        effective = self.compile(
            {
                "identity-demo": {
                    "name": "Identity Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "identity-demo.service"},
                    "authorization": {
                        "capabilities": [{"id": "admin", "title": "Administration"}],
                    },
                    "routes": {
                        "web": {
                            "target": {"type": "http", "port": 8080},
                            "exposure": {"type": "path", "paths": ["/demo/"]},
                            "auth": {"mode": "identity", "capability": "admin"},
                        }
                    },
                },
                "public-demo": {
                    "name": "Public Demo",
                    "workload": {"kind": "daemon", "activation": "persistent"},
                    "runtime": {"type": "systemd", "unit": "public-demo.service"},
                    "routes": {
                        "web": {
                            "target": {"type": "http", "port": 8090},
                            "exposure": {"type": "path", "paths": ["/public-demo/"]},
                            "auth": {"mode": "public"},
                        }
                    },
                },
            }
        )
        rendered = caddy.generate_caddyfile(effective)
        self.assertIn("X-Authentik-Groups", rendered)
        self.assertIn("missing_capability", rendered)
        self.assertIn("/public-demo/", rendered)
        caddy.validate_caddyfile(rendered, caddy_bin=self.caddy_bin)

    def test_on_demand_identity_route_with_wake_is_accepted_by_real_caddy(self):
        effective = self.compile(
            {
                "on-demand": {
                    "name": "On demand",
                    "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 60},
                    "runtime": {"type": "systemd", "unit": "on-demand.service"},
                    "routes": {
                        "web": {
                            "target": {"type": "http", "port": 8100},
                            "exposure": {"type": "path", "paths": ["/ondemand/"]},
                            "auth": {"mode": "identity"},
                        }
                    },
                }
            }
        )
        rendered = caddy.generate_caddyfile(effective, wake_socket="/run/nas-control/wake.sock")
        self.assertIn("/wake?service=on-demand", rendered)
        caddy.validate_caddyfile(rendered, caddy_bin=self.caddy_bin)

    def test_validate_helper_rejects_invalid_caddyfile(self):
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy.validate_caddyfile("this is not valid caddy syntax {", caddy_bin=self.caddy_bin)


if __name__ == "__main__":
    unittest.main()
