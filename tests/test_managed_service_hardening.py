from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc
import nas_service_caddy as caddy
import nas_feature_control as gate


class CaddySingleSourceTests(unittest.TestCase):
    def test_fragment_is_imported_by_caddy(self):
        text = pathlib.Path("modules/nas/config/managed-services.nix").read_text(encoding="utf-8")
        self.assertIn("caddy-managed.conf", text)
        self.assertIn("import", text)
        self.assertIn("restartTriggers", text)

    def test_generated_caddy_includes_forward_auth_and_uid(self):
        effective = {
            "endpoints": {
                "app:web": {
                    "transport": "https",
                    "targetPort": 8443,
                    "exposure": {"type": "hostname", "value": "app.example"},
                    "auth": {"mode": "forward-auth", "allow": "groups", "groups": ["family"]},
                }
            }
        }
        caddyfile = caddy.generate_caddyfile(effective)
        self.assertIn("forward_auth 127.0.0.1:9000", caddyfile)
        self.assertIn("Remote-UID", caddyfile)
        self.assertIn("transport http", caddyfile)
        self.assertIn("tls", caddyfile)

    def test_port_exposure_generates_site_block(self):
        effective = {
            "endpoints": {
                "app:web": {
                    "transport": "http",
                    "targetPort": 9000,
                    "exposure": {"type": "port", "value": 8443},
                    "auth": {"mode": "public"},
                }
            }
        }
        caddyfile = caddy.generate_caddyfile(effective)
        self.assertIn("https://nas.local:8443", caddyfile)
        self.assertIn("tls internal", caddyfile)

    def test_path_prefix_includes_strip(self):
        effective = {
            "endpoints": {
                "app:web": {
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "path", "value": "/photos", "prefix": True},
                    "auth": {"mode": "public"},
                }
            }
        }
        caddyfile = caddy.generate_caddyfile(effective)
        self.assertIn("uri strip_prefix /photos", caddyfile)
        self.assertIn("X-Forwarded-Prefix", caddyfile)


class ReserveCollideTests(unittest.TestCase):
    def test_reserved_path_rejected(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "conflicts with reserved"):
            msvc.validate_service("test", {
                "label": "Test",
                "enabled": True,
                "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/test/app.container", "startPolicy": "boot"},
                "endpoints": {
                    "web": {"transport": "http", "targetPort": 80, "exposure": {"type": "path", "value": "/api"}, "auth": {"mode": "public"}}
                }
            })

    def test_hostname_injection_rejected(self):
        with self.assertRaisesRegex(caddy.CaddyError, "contains invalid characters"):
            caddy._validate_exposure({"type": "hostname", "value": "evil.com\n header X: pwned"})

    def test_lan_host_collision_rejected(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "collides with NAS host"):
            msvc.validate_service("test", {
                "label": "Test",
                "enabled": True,
                "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/test/app.container", "startPolicy": "boot"},
                "endpoints": {
                    "web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "nas.local"}, "auth": {"mode": "public"}}
                }
            })


class AuthentikStableIdTests(unittest.TestCase):
    def test_group_pk_accepted(self):
        msvc.validate_service("test", {
            "label": "Test",
            "enabled": True,
            "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/test/app.container", "startPolicy": "boot"},
            "endpoints": {
                "web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "app.example"}, "auth": {"mode": "forward-auth", "groups": ["123", "550e8400-e29b-41d4-a716-446655440000"]}}
            }
        })

    def test_user_pk_accepted(self):
        msvc.validate_service("test", {
            "label": "Test",
            "enabled": True,
            "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/test/app.container", "startPolicy": "boot"},
            "endpoints": {
                "web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "app.example"}, "auth": {"mode": "forward-auth", "users": ["456", "550e8400-e29b-41d4-a716-446655440001"]}}
            }
        })


class GateTests(unittest.TestCase):
    def test_service_scope_validated(self):
        self.assertTrue(gate._is_valid_service_scope("service:my-app:web"))
        self.assertFalse(gate._is_valid_service_scope("service:../etc/passwd:foo"))
        self.assertFalse(gate._is_valid_service_scope("service:app"))
        self.assertFalse(gate._is_valid_service_scope("not-service:app:web"))

    def test_allow_default_deny(self):
        headers = {"Remote-User": "alice", "Remote-Groups": "family"}
        scope = "service:test:web"
        import tempfile, json, pathlib, os
        with tempfile.TemporaryDirectory() as tmp:
            effective_path = pathlib.Path(tmp) / "effective.json"
            effective = {
                "schemaVersion": 2,
                "generation": 1,
                "endpoints": {
                    "test:web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "test.local"}, "auth": {"mode": "forward-auth"}, "available": True}
                }
            }
            effective_path.write_text(json.dumps(effective), encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_EFFECTIVE_REGISTRY": str(effective_path)}):
                gate._EFFECTIVE_CACHE["mtime"] = 0.0
                self.assertFalse(gate.authorize_service_scope(scope, headers))

    def test_remote_uid_used(self):
        headers = {"Remote-User": "alice", "Remote-Groups": "family", "Remote-UID": "123"}
        scope = "service:test:web"
        import tempfile, json, pathlib, os
        with tempfile.TemporaryDirectory() as tmp:
            effective_path = pathlib.Path(tmp) / "effective.json"
            effective = {
                "schemaVersion": 2,
                "generation": 1,
                "endpoints": {
                    "test:web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "test.local"}, "auth": {"mode": "forward-auth", "allow": "users", "users": ["123"]}, "available": True}
                }
            }
            effective_path.write_text(json.dumps(effective), encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_EFFECTIVE_REGISTRY": str(effective_path)}):
                gate._EFFECTIVE_CACHE["mtime"] = 0.0
                self.assertTrue(gate.authorize_service_scope(scope, headers))
                headers2 = {"Remote-User": "bob", "Remote-Groups": "family"}
                self.assertFalse(gate.authorize_service_scope(scope, headers2))


if __name__ == "__main__":
    unittest.main()
