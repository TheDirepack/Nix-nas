from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_spec as v2  # noqa: E402


class ManagedServicesV2CaddyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def compile(self, service: dict) -> dict:
        return v2.compile_document({"schemaVersion": 3, "services": {"demo": service}}, self.schema)

    def base_service(self) -> dict:
        return {
            "name": "Demo",
            "workload": {"kind": "daemon", "activation": "persistent"},
            "runtime": {"type": "systemd", "unit": "demo.service"},
        }

    def test_identity_route_authorizes_in_caddy_before_proxy(self):
        service = self.base_service()
        service["authorization"] = {"capabilities": [{"id": "admin", "title": "Administration"}]}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity", "capability": "admin"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        self.assertIn("request_header -X-Authentik-Username", rendered)
        self.assertIn("forward_auth 127.0.0.1:9000", rendered)
        self.assertIn('uri "/identity/outpost.goauthentik.io/auth/caddy"', rendered)
        self.assertIn("not header_regexp X-Authentik-Groups", rendered)
        self.assertIn(r"application\\.demo\\.admin", rendered)
        self.assertIn("respond @v2_demo_web_missing_capability 403", rendered)
        self.assertLess(rendered.index("forward_auth 127.0.0.1:9000"), rendered.index("reverse_proxy 127.0.0.1:8080"))
        self.assertLess(rendered.index("missing_capability"), rendered.index("reverse_proxy 127.0.0.1:8080"))
        self.assertNotIn("nas-feature-control", rendered)
        self.assertNotIn("/authorize?", rendered)

    def test_public_and_upstream_routes_do_not_call_authentik(self):
        for mode in ("public", "upstream"):
            with self.subTest(mode=mode):
                service = self.base_service()
                service["routes"] = {
                    "web": {
                        "target": {"type": "http", "port": 8080},
                        "exposure": {"type": "path", "paths": ["/demo/"]},
                        "auth": {"mode": mode},
                    }
                }
                rendered = caddy.generate_caddyfile(self.compile(service))
                self.assertNotIn("forward_auth 127.0.0.1:9000", rendered)
                self.assertNotIn("copy_headers", rendered)
                self.assertIn("reverse_proxy 127.0.0.1:8080", rendered)

    def test_public_routes_strip_all_identity_headers(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "public"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        for header in caddy.IDENTITY_HEADERS:
            with self.subTest(header=header):
                self.assertIn(f"request_header -{header}", rendered)
        # Ensure stripping happens before proxy and no auth injection occurs
        self.assertLess(rendered.index("request_header -Remote-User"), rendered.index("reverse_proxy"))
        self.assertNotIn("Remote-User {http.request.header", rendered)

    def test_upstream_routes_strip_all_identity_headers(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "upstream"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        for header in caddy.IDENTITY_HEADERS:
            with self.subTest(header=header):
                self.assertIn(f"request_header -{header}", rendered)
        self.assertNotIn("forward_auth", rendered)

    def test_identity_route_strips_full_corpus(self):
        service = self.base_service()
        service["authorization"] = {"capabilities": [{"id": "admin", "title": "Administration"}]}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity", "capability": "admin"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        expected_headers = (
            "Remote-User",
            "Remote-Groups",
            "Remote-Name",
            "Remote-Email",
            "Remote-UID",
            "Remote-Role",
            "X-Authentik-Username",
            "X-Authentik-Groups",
            "X-Authentik-Name",
            "X-Authentik-Email",
            "X-Authentik-Uid",
            "X-Authentik-Jwt",
            "X-Authentik-Entitlements",
            "X-Authentik-Meta-Outpost",
            "X-Authentik-Meta-App",
            "X-Authentik-Meta-Provider",
            "X-Authentik-Meta-User",
            "X-Authentik-Meta-Is-Superuser",
            "X-Authentik-Role",
        )
        for header in expected_headers:
            with self.subTest(header=header):
                self.assertIn(f"request_header -{header}", rendered)
        # Corpus must match module constant
        self.assertEqual(set(caddy.IDENTITY_HEADERS), set(expected_headers))
        self.assertEqual(caddy.TRUSTED_IDENTITY_HEADERS, frozenset(expected_headers))
        # Stripping must occur before forward_auth
        self.assertLess(rendered.index("request_header -Remote-User"), rendered.index("forward_auth"))

    def test_wake_socket_rejects_newline_and_brace(self):
        service = self.base_service()
        service["workload"] = {"kind": "daemon", "activation": "on-demand", "idleSeconds": 60}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity"},
            }
        }
        effective = self.compile(service)
        for bad in ("/run/wake\n.sock", "/run/wake\r.sock", "/run/wake\x00.sock", "/run/wake{.sock", "/run/wake}.sock"):
            with self.subTest(bad=repr(bad)):
                with self.assertRaisesRegex(caddy.CaddyProjectionError, "absolute safe path"):
                    caddy.generate_caddyfile(effective, wake_socket=bad)

    def test_on_demand_route_requires_new_wake_boundary(self):
        service = self.base_service()
        service["workload"] = {"kind": "daemon", "activation": "on-demand", "idleSeconds": 60}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity"},
            }
        }
        effective = self.compile(service)
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "wake socket"):
            caddy.generate_caddyfile(effective)
        rendered = caddy.generate_caddyfile(effective, wake_socket="/run/nas-control/v2-wake.sock")
        capability_position = rendered.index("missing_capability")
        wake_position = rendered.index("/wake?service=demo")
        proxy_position = rendered.index("reverse_proxy 127.0.0.1:8080")
        self.assertLess(capability_position, wake_position)
        self.assertLess(wake_position, proxy_position)
        self.assertNotIn("Remote-User {http.request.header.Remote-User}", rendered)

    def test_on_demand_upstream_auth_fails_closed(self):
        service = self.base_service()
        service["workload"] = {"kind": "daemon", "activation": "on-demand", "idleSeconds": 60}
        service["routes"] = {
            "api": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/api/"]},
                "auth": {"mode": "upstream"},
            }
        }
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "pre-upstream authorization"):
            caddy.generate_caddyfile(self.compile(service), wake_socket="/run/nas-control/v2-wake.sock")

    def test_disabled_service_has_no_route(self):
        service = self.base_service()
        service["enabled"] = False
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "public"},
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        self.assertNotIn("/demo/", rendered)
        self.assertNotIn("reverse_proxy", rendered)

    def test_hostname_route_cannot_duplicate_appliance_site(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "hostname", "hostnames": ["nas.local"]},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "collides"):
            caddy.generate_caddyfile(self.compile(service), lan_host="nas.local")

    def test_unix_target_and_proxy_headers(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "unix-http", "socket": "/run/demo/http.sock"},
                "exposure": {"type": "path", "paths": ["/demo"]},
                "auth": {"mode": "public"},
                "proxy": {
                    "stripPrefix": "/demo",
                    "requestHeaders": {"X-Forwarded-Prefix": "/demo"},
                    "removeRequestHeaders": ["X-Untrusted"],
                    "responseHeaders": {"X-Frame-Options": "SAMEORIGIN"},
                    "requireHeaders": {"Origin": "https://nas.local"},
                },
            }
        }
        rendered = caddy.generate_caddyfile(self.compile(service))
        self.assertIn('not header Origin "https://nas.local"', rendered)
        self.assertIn("request_header -X-Untrusted", rendered)
        self.assertIn('request_header X-Forwarded-Prefix "/demo"', rendered)
        self.assertIn('uri strip_prefix "/demo"', rendered)
        self.assertIn("reverse_proxy unix//run/demo/http.sock", rendered)
        self.assertIn('header_down X-Frame-Options "SAMEORIGIN"', rendered)

    def test_static_request_headers_cannot_forge_trusted_identity(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "identity"},
                "proxy": {"requestHeaders": {"Remote-User": "admin"}},
            }
        }
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "trusted identity"):
            caddy.generate_caddyfile(self.compile(service))

    def test_trusted_identity_header_projection_requires_identity_auth(self):
        service = self.base_service()
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/demo/"]},
                "auth": {"mode": "public"},
                "proxy": {"trustedIdentityHeaders": ["Remote-User"]},
            }
        }
        with self.assertRaisesRegex(caddy.CaddyProjectionError, "requires identity"):
            caddy.generate_caddyfile(self.compile(service))


if __name__ == "__main__":
    unittest.main()
