from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

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

    def test_validate_service_id_and_labels(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid service ID"):
            msvc.validate_service("Bad_ID", {"label": "x", "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/x/"}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "label"):
            msvc.validate_service("ok-svc", {"label": "", "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/x/"}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "label"):
            msvc.validate_service("ok-svc", {"label": "x" * 65, "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/x/"}})

    def test_validate_runtime_and_source(self):
        base = {"label": "X", "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml"}}
        bad_runtime = dict(base)
        bad_runtime["runtime"] = {"type": "k8s", "source": "/var/lib/nas-control/apps/x/"}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime.type invalid"):
            msvc.validate_service("x", bad_runtime)
        bad_source = dict(base)
        bad_source["runtime"] = {"type": "compose", "source": "/etc/passwd"}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime.source"):
            msvc.validate_service("x", bad_source)
        # hostPath not absolute
        bad_mount = dict(base)
        bad_mount["storage"] = [{"hostPath": "relative", "guestPath": "/data"}]
        with self.assertRaisesRegex(msvc.ManagedServiceError, "hostPath must be absolute"):
            msvc.validate_service("x", bad_mount)
        # guestPath not absolute
        bad_guest = dict(base)
        bad_guest["storage"] = [{"hostPath": "/tank/data", "guestPath": "data"}]
        with self.assertRaisesRegex(msvc.ManagedServiceError, "guestPath must be absolute"):
            msvc.validate_service("x", bad_guest)
        # traversal
        traversal = dict(base)
        traversal["storage"] = [{"hostPath": "/tank/../etc", "guestPath": "/data"}]
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must not contain"):
            msvc.validate_service("x", traversal)

    def test_validate_endpoints(self):
        base = {"label": "X", "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/x/compose.yaml"}}
        bad_endpoint = dict(base)
        bad_endpoint["endpoints"] = {"Bad ID": {"targetPort": 80}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "endpoint .* invalid"):
            msvc.validate_service("x", bad_endpoint)
        bad_port = dict(base)
        bad_port["endpoints"] = {"web": {"targetPort": 0}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid port"):
            msvc.validate_service("x", bad_port)
        bad_hostname = dict(base)
        bad_hostname["endpoints"] = {"web": {"targetPort": 80, "exposure": {"type": "hostname", "value": "bad host"}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid hostname"):
            msvc.validate_service("x", bad_hostname)
        bad_dns = dict(base)
        bad_dns["endpoints"] = {"web": {"targetPort": 80, "exposure": {"type": "dns", "value": "bad_dns"}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid hostname"):
            msvc.validate_service("x", bad_dns)
        bad_group = dict(base)
        bad_group["endpoints"] = {"web": {"targetPort": 80, "auth": {"mode": "forward-auth", "groups": ["bad group!"]}}}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid Authentik group"):
            msvc.validate_service("x", bad_group)
        # valid dns endpoint passes
        ok = dict(base)
        ok["endpoints"] = {"web": {"targetPort": 80, "exposure": {"type": "dns", "value": "app.nas.local"}}}
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
            self.assertEqual(msvc.load_store(missing), {"schemaVersion": 2, "services": {}})
            bad_json = pathlib.Path(tmp) / "bad.json"
            bad_json.write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(msvc.ManagedServiceError, "Invalid JSON"):
                msvc.load_store(bad_json)
            wrong_version = pathlib.Path(tmp) / "wrong.json"
            wrong_version.write_text('{"schemaVersion": 99, "services": {}}', encoding="utf-8")
            with self.assertRaisesRegex(msvc.ManagedServiceError, "Unsupported schemaVersion"):
                msvc.load_store(wrong_version)
            not_object = pathlib.Path(tmp) / "not.json"
            not_object.write_text('{"schemaVersion": 2, "services": []}', encoding="utf-8")
            with self.assertRaisesRegex(msvc.ManagedServiceError, "services must be an object"):
                msvc.load_store(not_object)
            unreadable_dir = pathlib.Path(tmp) / "dir"
            unreadable_dir.mkdir()
            with self.assertRaisesRegex(msvc.ManagedServiceError, "Unable to read"):
                msvc.load_store(unreadable_dir)

    def test_atomic_write_rejects_wrong_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pathlib.Path(tmp) / "services.json"
            with self.assertRaisesRegex(msvc.ManagedServiceError, "wrong schemaVersion"):
                msvc.atomic_write_store({"schemaVersion": 1, "services": {}}, store)

    def test_effective_registry_missing_builtin(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pathlib.Path(tmp) / "services.json"
            missing_builtin = pathlib.Path(tmp) / "missing-builtin.json"
            msvc.atomic_write_store({"schemaVersion": 2, "services": {}}, store)
            eff = msvc.effective_registry(missing_builtin, store)
            self.assertEqual(eff["endpoints"], {})

    def test_portal_projection_variants(self):
        effective = {
            "schemaVersion": 2,
            "generation": 3,
            "endpoints": {
                "path-svc": {
                    "label": "Path",
                    "linkKey": "path",
                    "exposure": {"type": "path", "value": "/console/"},
                    "portal": {"category": "Admin", "icon": "wrench"},
                    "available": True,
                    "auth": {"mode": "forward-auth"},
                },
                "port-svc": {
                    "label": "Port",
                    "linkKey": "port",
                    "exposure": {"type": "port", "value": 8080},
                },
                "hidden-svc": {
                    "label": "Hidden",
                    "exposure": {"type": "path", "value": "/secret/"},
                    "portal": {"visible": False},
                },
            },
        }
        portal = msvc.portal_projection(effective)
        by_id = {entry["id"]: entry for entry in portal["entries"]}
        self.assertEqual(by_id["path-svc"]["url"], "/console/")
        self.assertEqual(by_id["path-svc"]["category"], "Admin")
        self.assertEqual(by_id["path-svc"]["icon"], "wrench")
        self.assertEqual(by_id["port-svc"]["url"], "https://nas.local:8080/")
        self.assertEqual(by_id["port-svc"]["access"]["mode"], "admin")
        self.assertNotIn("hidden-svc", by_id)
        # effective is None -> use default registry (real default paths absent on host)
        with mock.patch.object(msvc, "effective_registry", side_effect=msvc.ManagedServiceError("no store")):
            with self.assertRaises(msvc.ManagedServiceError):
                msvc.portal_projection(None)

    def test_write_portal(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pathlib.Path(tmp) / "services.json"
            builtin = pathlib.Path(tmp) / "builtin.json"
            effective = pathlib.Path(tmp) / "effective.json"
            portal = pathlib.Path(tmp) / "portal.json"
            builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {"cockpit": {"label": "Cockpit", "publicPath": "/console/", "port": 9092, "units": ["cockpit.socket"], "access": "admin", "available": True, "linkKey": "console"}}}))
            msvc.atomic_write_store({"schemaVersion": 2, "services": {}}, store)
            # write_portal uses def-time bound default paths (/run/nas-control). Patch the
            # registry source and lower-level fs primitives to redirect writes to tmp.
            base_effective = msvc.effective_registry(builtin, store)
            fd, tmp_name = tempfile.mkstemp(prefix=".portal.json.", dir=tmp)
            os.close(fd)
            with mock.patch.object(msvc, "effective_registry", return_value=base_effective):
                with mock.patch.object(pathlib.Path, "mkdir"):
                    with mock.patch.object(pathlib.Path, "replace"):
                        with mock.patch.object(msvc.tempfile, "mkstemp", return_value=(os.open(tmp_name, os.O_WRONLY | os.O_TRUNC), tmp_name)):
                            with mock.patch.object(msvc.os, "fsync"), mock.patch.object(msvc.os, "open", return_value=0), mock.patch.object(msvc.os, "close"):
                                result = msvc.write_portal()
            self.assertIn("cockpit", {e["id"]: e for e in result["entries"]})

    def test_main_reconcile_validate_show_and_errors(self):
        store = {"schemaVersion": 2, "services": {}}
        effective = {"schemaVersion": 2, "generation": 1, "endpoints": {}, "services": {}}
        with mock.patch.object(msvc, "write_effective", return_value=effective):
            with mock.patch.object(msvc, "write_portal", return_value={"entries": []}):
                self.assertEqual(msvc.main(["reconcile"]), 0)
        with mock.patch.object(msvc, "load_store", return_value=store):
            with mock.patch.object(msvc, "effective_registry", return_value=effective):
                self.assertEqual(msvc.main(["validate"]), 0)
        with mock.patch.object(msvc, "effective_registry", return_value=effective):
            self.assertEqual(msvc.main(["show"]), 0)
            self.assertEqual(msvc.main(["show", "--json"]), 0)
        with self.assertRaises(SystemExit):
            msvc.main(["nope"])
        # error path: unreadable store
        with mock.patch.object(msvc, "load_store", side_effect=msvc.ManagedServiceError("boom")):
            self.assertEqual(msvc.main(["validate"]), 1)
        with mock.patch.object(msvc, "effective_registry", side_effect=OSError("io")):
            self.assertEqual(msvc.main(["show"]), 1)


if __name__ == "__main__":
    unittest.main()
