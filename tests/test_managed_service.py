from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc


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
            # portal should not contain secrets or host paths
            self.assertNotIn("/tank", json.dumps(portal))

    def test_no_sqlite_dependency(self):
        # Ensure the module does not import sqlite3 (mentioning "no sqlite" in docs is ok)
        import importlib.util
        spec = importlib.util.find_spec("nas_managed_service")
        assert spec is not None
        source = pathlib.Path(spec.origin).read_text(encoding="utf-8") if spec.origin else ""
        self.assertNotIn("import sqlite3", source)
        self.assertNotIn("from sqlite", source)


if __name__ == "__main__":
    unittest.main()
