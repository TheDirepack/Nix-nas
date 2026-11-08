from __future__ import annotations

import os
import hashlib
import pathlib
import shutil
import sys
import unittest
import http.client
import socket
import subprocess
import tempfile
import time

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


class ManagedServicesV2CaddyValidationDiscoveryTests(unittest.TestCase):
    def test_validation_suite_is_discoverable_without_caddy(self) -> None:
        binary = _caddy_binary()
        self.assertTrue(binary is None or pathlib.Path(binary).is_file())


class ManagedServicesV2RealCaddyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)
        cls.caddy_bin = _caddy_binary()
        if cls.caddy_bin is None:
            raise unittest.SkipTest("caddy binary not available")

    def compile(self, services: dict) -> dict:
        return v2.compile_document({"schemaVersion": 3, "services": services}, self.schema)

    def test_proxy_probe_methods_stop_at_edge_and_normal_options_remains_available(self):
        assert self.caddy_bin is not None
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with tempfile.TemporaryDirectory() as raw:
            config = pathlib.Path(raw) / "Caddyfile"
            policy = (SERVICES / "nas_policy/proxy-probes.caddy").read_text()
            config.write_text(
                "{\n  admin off\n}\nhttp://127.0.0.1:"
                + str(port)
                + " {\n"
                + policy
                + "\nhandle /identity {\n  redir * /identity/\n}\n"
                + 'respond "application" 200\n}\n'
            )
            process = subprocess.Popen(
                [self.caddy_bin, "run", "--config", str(config), "--adapter", "caddyfile"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                for attempt in range(100):
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.02)
                cors = {"Origin": "https://example.test", "Access-Control-Request-Method": "POST"}
                for path, method, headers, expected, body in (
                    ("/console/", "TRACE", {}, 405, b""),
                    ("/console/", "TRACK", {}, 405, b""),
                    ("/console/", "OPTIONS", {"Max-Forwards": "0"}, 405, b""),
                    ("/console/", "OPTIONS", {"Max-Forwards": "7"}, 405, b""),
                    ("/console/", "OPTIONS", cors, 200, b"application"),
                    ("/console/", "GET", {}, 200, b"application"),
                    ("/console/", "POST", {}, 200, b"application"),
                    ("/console/", "PROPFIND", {}, 200, b"application"),
                    ("/identity", "TRACE", {}, 405, b""),
                    ("/identity", "TRACK", {}, 405, b""),
                    ("/identity", "OPTIONS", {"Max-Forwards": "7"}, 405, b""),
                    ("/identity", "GET", {}, 302, b""),
                    ("/identity", "OPTIONS", cors, 302, b""),
                ):
                    with self.subTest(path=path, method=method, headers=headers):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                        connection.request(method, path, headers=headers)
                        response = connection.getresponse()
                        self.assertEqual(response.status, expected)
                        self.assertEqual(response.read(), body)
                        connection.close()
            finally:
                process.terminate()
                process.wait(timeout=5)

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

    def test_on_demand_identity_route_with_native_activation_is_accepted_by_real_caddy(self):
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
        rendered = caddy.generate_caddyfile(effective)
        route_name = "h_" + hashlib.sha256(b"on-demand\0web").hexdigest()
        self.assertIn(f"reverse_proxy unix//run/nas-control/activate/{route_name}.sock", rendered)
        self.assertNotIn("/wake?", rendered)
        caddy.validate_caddyfile(rendered, caddy_bin=self.caddy_bin)

    def test_validate_helper_rejects_invalid_caddyfile(self):
        with self.assertRaises(caddy.CaddyProjectionError):
            caddy.validate_caddyfile("this is not valid caddy syntax {", caddy_bin=self.caddy_bin)


if __name__ == "__main__":
    unittest.main()
