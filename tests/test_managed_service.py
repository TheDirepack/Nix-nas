from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest

import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc
import nas_service_authentik  # noqa: F401 - imported for contract coverage
import nas_service_caddy
import nas_service_firewall  # noqa: F401
import nas_service_runtime_compose  # noqa: F401
import nas_service_runtime_libvirt  # noqa: F401
import nas_service_runtime_podman  # noqa: F401


class ManagedServiceTests(unittest.TestCase):
    def test_accept_list_rejects_outside_root(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "allow-list"):
            msvc.validate_service("test-svc", {
                "label": "Test",
                "enabled": True,
                "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/test-svc/compose.yaml", "startPolicy": "manual"},
                "storage": [{"hostPath": "/etc/passwd", "guestPath": "/data", "mode": "ro"}],
                "endpoints": {}
            })

    def test_accept_list_allows_tank(self):
        msvc.validate_service("photos", {
            "label": "Photos",
            "enabled": True,
            "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/photos/compose.yaml", "startPolicy": "boot"},
            "storage": [{"hostPath": "/tank/photos", "guestPath": "/photos", "mode": "rw"}],
            "endpoints": {
                "web": {
                    "transport": "http",
                    "targetPort": 2283,
                    "exposure": {"type": "hostname", "value": "photos.local"},
                    "auth": {"mode": "forward-auth", "allow": "groups", "groups": ["family"]}
                }
            }
        })

    def test_atomic_write_and_effective_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pathlib.Path(tmp) / "services.json"
            builtin = pathlib.Path(tmp) / "builtin.json"
            effective = pathlib.Path(tmp) / "effective.json"
            builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {"cockpit": {"label": "Cockpit", "publicPath": "/console/", "port": 9092, "units": ["cockpit.socket"], "access": "admin", "available": True, "linkKey": "console"}}}))
            data = {"schemaVersion": 2, "services": {
                "immich": {
                    "label": "Immich",
                    "enabled": True,
                    "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/immich/compose.yaml", "startPolicy": "boot"},
                    "endpoints": {
                        "web": {"transport": "http", "targetPort": 2283, "exposure": {"type": "hostname", "value": "immich.local"}, "auth": {"mode": "forward-auth"}}
                    }
                }
            }}
            msvc.atomic_write_store(data, store)
            eff = msvc.effective_registry(builtin, store)
            self.assertIn("cockpit", eff["endpoints"])
            self.assertIn("immich:web", eff["endpoints"])
            msvc.write_effective(builtin, store, effective)
            self.assertTrue(effective.exists())
            portal = msvc.portal_projection(eff)
            self.assertNotIn("/tank", json.dumps(portal))

    def test_no_sqlite_dependency(self):
        import importlib.util
        spec = importlib.util.find_spec("nas_managed_service")
        assert spec is not None
        source = pathlib.Path(spec.origin).read_text(encoding="utf-8") if spec.origin else ""
        self.assertNotIn("import sqlite3", source)
        self.assertNotIn("from sqlite", source)

    def test_validate_service_id_and_labels(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid service ID"):
            msvc.validate_service("Bad_ID", {"label": "x", "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/x/"}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "label"):
            msvc.validate_service("ok-svc", {"label": "", "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/x/"}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "label"):
            msvc.validate_service("ok-svc", {"label": "x" * 65, "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/x/"}})

    def test_validate_runtime_and_source(self):
        base = {"label": "X", "enabled": True, "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml"}}
        bad_runtime = dict(base)
        bad_runtime["runtime"] = {"type": "k8s", "source": "/var/lib/nas-control/apps/x/"}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime.type invalid"):
            msvc.validate_service("x", bad_runtime)
        bad_source = dict(base)
        bad_source["runtime"] = {"type": "compose", "source": "/etc/passwd"}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime.source"):
            msvc.validate_service("x", bad_source)
        bad_mount = dict(base)
        bad_mount["storage"] = [{"hostPath": "relative", "guestPath": "/data"}]
        with self.assertRaisesRegex(msvc.ManagedServiceError, "hostPath must be absolute"):
            msvc.validate_service("x", bad_mount)
        bad_guest = dict(base)
        bad_guest["storage"] = [{"hostPath": "/tank/data", "guestPath": "data"}]
        with self.assertRaisesRegex(msvc.ManagedServiceError, "guestPath must be absolute"):
            msvc.validate_service("x", bad_guest)
        traversal = dict(base)
        traversal["storage"] = [{"hostPath": "/tank/../etc", "guestPath": "/data"}]
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must not contain"):
            msvc.validate_service("x", traversal)

    def test_validate_endpoints(self):
        base = {"label": "X", "enabled": True, "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml"}}
        bad_endpoint = dict(base)
        bad_endpoint["endpoints"] = {"Bad ID": {"targetPort": 80}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "endpoint .* invalid"):
            msvc.validate_service("x", bad_endpoint)
        bad_port = dict(base)
        bad_port["endpoints"] = {"web": {"transport": "http", "targetPort": 0, "exposure": {"type": "hostname", "value": "app.local"}, "auth": {"mode": "public"}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid port"):
            msvc.validate_service("x", bad_port)
        bad_hostname = dict(base)
        bad_hostname["endpoints"] = {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "bad host"}, "auth": {"mode": "public"}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid hostname"):
            msvc.validate_service("x", bad_hostname)
        bad_dns = dict(base)
        bad_dns["endpoints"] = {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "dns", "value": "bad_dns"}, "auth": {"mode": "public"}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid hostname"):
            msvc.validate_service("x", bad_dns)
        bad_group = dict(base)
        bad_group["endpoints"] = {"web": {"targetPort": 80, "exposure": {"type": "hostname", "value": "app.local"}, "auth": {"mode": "forward-auth", "groups": ["bad group!"]}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid Authentik group"):
            msvc.validate_service("x", bad_group)
        ok = dict(base)
        ok["endpoints"] = {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "dns", "value": "app.service.local"}, "auth": {"mode": "public"}}}
        msvc.validate_service("x", ok)

    def test_validate_image_and_port(self):
        for bad in ("x" * 513, "not a valid ref!", "IMAGE WITH SPACES"):
            with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid image"):
                msvc._validate_image(bad)
        self.assertEqual(msvc._validate_image("ghcr.io/user/app:1.2.3"), "ghcr.io/user/app:1.2.3")
        for bad in (0, 70000, "80"):
            with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid port"):
                msvc._validate_port(bad)
        self.assertEqual(msvc._validate_port(8080), 8080)

    def test_portal_projection_port_url_branch(self):
        effective = {
            "schemaVersion": 2,
            "generation": 1,
            "endpoints": {
                "game-svc": {
                    "label": "Game",
                    "linkKey": "game",
                    "exposure": {"type": "port", "value": 25565},
                }
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
            service = {"label": "X", "enabled": True, "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml"}, "endpoints": {}}
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
        base = {"label": "X", "enabled": True, "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml"}}
        collision = dict(base)
        collision["endpoints"] = {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "nas.local"}, "auth": {"mode": "public"}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "collides with NAS host"):
            msvc.validate_service("x", collision)

    def test_reserved_path_detection(self):
        base = {"label": "X", "enabled": True, "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml"}}
        collision = dict(base)
        collision["endpoints"] = {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "path", "value": "/api"}, "auth": {"mode": "public"}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "reserved"):
            msvc.validate_service("x", collision)


if __name__ == "__main__":
    unittest.main()
