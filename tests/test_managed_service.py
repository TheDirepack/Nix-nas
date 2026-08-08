from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_managed_service as msvc  # noqa: E402
import nas_service_caddy  # noqa: E402


class ManagedServiceTests(unittest.TestCase):
    def test_validate_service_id_and_labels(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "service id"):
            msvc.validate_service("Bad_ID", {"label": "x", "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "label"):
            msvc.validate_service("x", {"label": "", "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"}})

    def test_validate_runtime_and_source(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime type"):
            msvc.validate_service("x", {"label": "X", "runtime": {"type": "bogus", "source": "/var/lib/nas-control/apps/x/file", "startPolicy": "manual"}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime source"):
            msvc.validate_service("x", {"label": "X", "runtime": {"type": "compose", "source": "/tmp/compose.yaml", "startPolicy": "manual"}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "startPolicy"):
            msvc.validate_service("x", {"label": "X", "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "always"}})

    def test_validate_image_and_port(self):
        service = {
            "label": "X",
            "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"},
            "image": "docker.io/library/nginx@sha256:" + "a" * 64,
            "endpoints": {"web": {"transport": "http", "targetPort": 8080, "exposure": {"type": "path", "value": "/x"}, "auth": {"mode": "required"}}},
        }
        msvc.validate_service("x", service)
        bad = json.loads(json.dumps(service))
        bad["image"] = "nginx:latest"
        with self.assertRaisesRegex(msvc.ManagedServiceError, "digest"):
            msvc.validate_service("x", bad)
        bad = json.loads(json.dumps(service))
        bad["endpoints"]["web"]["targetPort"] = 70000
        with self.assertRaisesRegex(msvc.ManagedServiceError, "targetPort"):
            msvc.validate_service("x", bad)

    def test_validate_endpoints(self):
        base = {"label": "X", "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"}}
        cases = [
            ({"web": {"transport": "ftp", "targetPort": 80, "exposure": {"type": "path", "value": "/x"}, "auth": {"mode": "public"}}}, "transport"),
            ({"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "bogus", "value": "/x"}, "auth": {"mode": "public"}}}, "exposure type"),
            ({"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "path", "value": "x"}, "auth": {"mode": "public"}}}, "path"),
            ({"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "BAD_HOST"}, "auth": {"mode": "public"}}}, "hostname"),
            ({"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "port", "value": 70000}, "auth": {"mode": "public"}}}, "port"),
            ({"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "path", "value": "/x"}, "auth": {"mode": "bogus"}}}, "auth mode"),
        ]
        for endpoints, message in cases:
            service = dict(base)
            service["endpoints"] = endpoints
            with self.assertRaisesRegex(msvc.ManagedServiceError, message):
                msvc.validate_service("x", service)

    def test_reserved_path_detection(self):
        service = {
            "label": "X",
            "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"},
            "endpoints": {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "path", "value": "/api/foo"}, "auth": {"mode": "public"}}},
        }
        with self.assertRaisesRegex(msvc.ManagedServiceError, "reserved"):
            msvc.validate_service("x", service)

    def test_accept_list_allows_tank(self):
        service = {
            "label": "X",
            "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"},
            "storage": [{"hostPath": "/tank/apps/x", "mountPath": "/data", "readOnly": False}],
        }
        msvc.validate_service("x", service)

    def test_accept_list_rejects_outside_root(self):
        service = {
            "label": "X",
            "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"},
            "storage": [{"hostPath": "/etc", "mountPath": "/data", "readOnly": False}],
        }
        with self.assertRaisesRegex(msvc.ManagedServiceError, "hostPath"):
            msvc.validate_service("x", service)

    def test_no_sqlite_dependency(self):
        source = (SERVICES / "nas_managed_service.py").read_text(encoding="utf-8")
        self.assertNotIn("sqlite3", source)

    def test_atomic_write_and_effective_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pathlib.Path(tmp) / "services.json"
            builtin = pathlib.Path(tmp) / "builtin.json"
            builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {"builtin:web": {"publicPath": "/builtin"}}}), encoding="utf-8")
            service = {
                "label": "X",
                "enabled": True,
                "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"},
                "endpoints": {"web": {"transport": "http", "targetPort": 8080, "exposure": {"type": "hostname", "value": "app.service.local"}, "auth": {"mode": "public"}}},
            }
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, store)
            effective = msvc.effective_registry(builtin, store)
            self.assertIn("builtin:web", effective["endpoints"])
            self.assertIn("x:web", effective["endpoints"])
            self.assertTrue(effective["endpoints"]["x:web"]["available"])
            service["enabled"] = False
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, store)
            effective = msvc.effective_registry(builtin, store)
            self.assertFalse(effective["endpoints"]["x:web"]["available"])

    def test_portal_projection_port_url_branch(self):
        effective = {
            "schemaVersion": 2,
            "generation": 1,
            "services": {"game": {"label": "Game", "enabled": True}},
            "endpoints": {
                "game:web": {"serviceId": "game", "endpointId": "web", "transport": "http", "targetPort": 25565, "exposure": {"type": "port", "value": 25565}, "auth": {"mode": "public"}, "available": True},
            },
        }
        portal = msvc.portal_projection(effective)
        self.assertEqual(portal["entries"][0]["url"], "https://nas.local:25565/")

    def test_load_store_edge_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "missing.json"
            result = msvc.load_store(missing)
            self.assertEqual(result["schemaVersion"], 2)
            self.assertEqual(result["services"], {})
            bad_json = pathlib.Path(tmp) / "bad.json"
            bad_json.write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid JSON"):
                msvc.load_store(bad_json)

    def test_atomic_write_store_mode_and_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "services.json"
            data = {"schemaVersion": 2, "generation": 1, "services": {}}
            msvc.atomic_write_store(data, path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(msvc.load_store(path)["generation"], 1)
            msvc.atomic_write_store(data, path)
            self.assertEqual(msvc.load_store(path)["generation"], 2)

    def test_effective_registry_reflects_service_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pathlib.Path(tmp) / "services.json"
            builtin = pathlib.Path(tmp) / "builtin.json"
            builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {}}), encoding="utf-8")
            service = {
                "label": "X",
                "enabled": True,
                "runtime": {
                    "type": "compose",
                    "source": "/var/lib/nas-control/apps/x/compose.yaml",
                    "startPolicy": "manual",
                },
                "endpoints": {},
            }
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, store)
            self.assertIn("x", msvc.effective_registry(builtin, store)["services"])
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {}}, store)
            self.assertNotIn("x", msvc.effective_registry(builtin, store)["services"])

    def test_port_collision_detection(self):
        effective = {
            "schemaVersion": 2,
            "generation": 1,
            "endpoints": {
                "a:web": {"transport": "http", "targetPort": 80, "exposure": {"type": "port", "value": 8080}, "auth": {"mode": "public"}},
                "b:web": {"transport": "http", "targetPort": 81, "exposure": {"type": "port", "value": 8080}, "auth": {"mode": "public"}},
            },
        }
        with self.assertRaisesRegex(nas_service_caddy.CaddyError, "Duplicate exposure"):
            nas_service_caddy.generate_caddy_fragment(effective)

    def test_hostname_collision_detection(self):
        base = {"label": "X", "enabled": True, "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml", "startPolicy": "manual"}}
        collision = dict(base)
        collision["endpoints"] = {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "nas.local"}, "auth": {"mode": "public"}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "collides with NAS host"):
            msvc.validate_service("x", collision)


if __name__ == "__main__":
    unittest.main()
