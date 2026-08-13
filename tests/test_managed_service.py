from __future__ import annotations

import contextlib
import io
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

import nas_managed_service as msvc  # noqa: E402
import nas_service_authentik  # noqa: E402
import nas_service_caddy  # noqa: E402
import nas_service_firewall  # noqa: E402
import nas_service_runtime_compose  # noqa: E402
import nas_service_runtime_libvirt  # noqa: E402
import nas_service_runtime_podman  # noqa: E402


def service_template(runtime_type: str = "compose") -> dict:
    suffix = "compose.yaml" if runtime_type == "compose" else "definition"
    return {
        "label": "X",
        "enabled": True,
        "runtime": {
            "type": runtime_type,
            "source": f"/var/lib/nas-control/apps/x/{suffix}",
            "startPolicy": "manual",
        },
    }


def visible_endpoint(exposure: dict | None = None) -> dict:
    return {
        "transport": "http",
        "targetPort": 8080,
        "exposure": exposure or {"type": "path", "value": "/managed"},
        "auth": {"mode": "public"},
        "portal": {"visible": True, "category": "Tools", "icon": "box"},
    }


class ManagedServiceTests(unittest.TestCase):
    def test_validate_service_id_and_labels(self):
        with self.assertRaisesRegex(msvc.ManagedServiceError, "(?i)service id"):
            msvc.validate_service("Bad_ID", service_template())
        service = service_template()
        service["label"] = ""
        with self.assertRaisesRegex(msvc.ManagedServiceError, "label"):
            msvc.validate_service("x", service)

    def test_validate_runtime_and_source(self):
        service = service_template("bogus")
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime.type"):
            msvc.validate_service("x", service)
        service = service_template()
        service["runtime"]["source"] = "/tmp/compose.yaml"
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime.source"):
            msvc.validate_service("x", service)

    def test_schema_enforces_start_policy_transport_and_storage_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "services.json"
            service = service_template()
            service["runtime"]["startPolicy"] = "always"
            with self.assertRaisesRegex(msvc.ManagedServiceError, "startPolicy"):
                msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, path)

            service = service_template()
            service["endpoints"] = {
                "web": {
                    "transport": "ftp",
                    "targetPort": 80,
                    "exposure": {"type": "path", "value": "/x"},
                    "auth": {"mode": "public"},
                }
            }
            with self.assertRaisesRegex(msvc.ManagedServiceError, "transport"):
                msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, path)

    def test_validate_image_and_port(self):
        service = service_template()
        service["runtime"]["image"] = "docker.io/library/nginx@sha256:" + "a" * 64
        service["endpoints"] = {
            "web": {
                "transport": "http",
                "targetPort": 8080,
                "exposure": {"type": "path", "value": "/x"},
                "auth": {"mode": "forward-auth"},
            }
        }
        msvc.validate_service("x", service)
        bad = json.loads(json.dumps(service))
        bad["endpoints"]["web"]["targetPort"] = 70000
        with self.assertRaisesRegex(msvc.ManagedServiceError, "port"):
            msvc.validate_service("x", bad)

    def test_validate_endpoints(self):
        cases = [
            (
                {
                    "web": {
                        "transport": "http",
                        "targetPort": 80,
                        "exposure": {"type": "bogus", "value": "/x"},
                        "auth": {"mode": "public"},
                    }
                },
                "exposure.type",
            ),
            (
                {
                    "web": {
                        "transport": "http",
                        "targetPort": 80,
                        "exposure": {"type": "path", "value": "x"},
                        "auth": {"mode": "public"},
                    }
                },
                "path",
            ),
            (
                {
                    "web": {
                        "transport": "http",
                        "targetPort": 80,
                        "exposure": {"type": "hostname", "value": "BAD_HOST"},
                        "auth": {"mode": "public"},
                    }
                },
                "hostname",
            ),
            (
                {
                    "web": {
                        "transport": "http",
                        "targetPort": 80,
                        "exposure": {"type": "port", "value": 70000},
                        "auth": {"mode": "public"},
                    }
                },
                "port",
            ),
            (
                {
                    "web": {
                        "transport": "http",
                        "targetPort": 80,
                        "exposure": {"type": "path", "value": "/x"},
                        "auth": {"mode": "bogus"},
                    }
                },
                "auth.mode",
            ),
        ]
        for endpoints, message in cases:
            with self.subTest(message=message):
                service = service_template()
                service["endpoints"] = endpoints
                with self.assertRaisesRegex(msvc.ManagedServiceError, message):
                    msvc.validate_service("x", service)

    def test_validation_rejects_malformed_runtime_auth_and_storage_fields(self):
        service = service_template()
        service["runtime"] = []
        with self.assertRaisesRegex(msvc.ManagedServiceError, "runtime must be object"):
            msvc.validate_service("x", service)

        service = service_template()
        service["storage"] = ["not-an-object"]
        with self.assertRaisesRegex(msvc.ManagedServiceError, "storage entry"):
            msvc.validate_service("x", service)

        for auth, message in (
            ({"mode": "public", "allow": "nobody"}, "auth.allow"),
            ({"mode": "public", "groups": "admins"}, "auth.groups"),
            ({"mode": "public", "users": "alice"}, "auth.users"),
            ({"mode": "public", "groups": ["bad group!"]}, "group ID"),
            ({"mode": "public", "users": ["bad user!"]}, "user ID"),
        ):
            service = service_template()
            service["endpoints"] = {"web": {**visible_endpoint(), "auth": auth}}
            with self.subTest(auth=auth):
                with self.assertRaisesRegex(msvc.ManagedServiceError, message):
                    msvc.validate_service("x", service)

    def test_reserved_path_detection(self):
        service = service_template()
        service["endpoints"] = {
            "web": {
                "transport": "http",
                "targetPort": 80,
                "exposure": {"type": "path", "value": "/api/foo"},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(msvc.ManagedServiceError, "reserved"):
            msvc.validate_service("x", service)

    def test_storage_allow_list(self):
        service = service_template()
        service["storage"] = [{"hostPath": "/tank/apps/x", "guestPath": "/data", "mode": "rw"}]
        msvc.validate_service("x", service)
        service["storage"][0]["hostPath"] = "/etc"
        with self.assertRaisesRegex(msvc.ManagedServiceError, "hostPath"):
            msvc.validate_service("x", service)

    def test_adapter_planners_are_directly_covered(self):
        compose = service_template("compose")
        self.assertEqual(
            nas_service_runtime_compose.plan_compose("x", compose)["runtime"],
            "podman-compose",
        )

        quadlet = service_template("quadlet")
        quadlet["runtime"]["source"] = "/var/lib/nas-control/apps/x/app.container"
        self.assertEqual(
            nas_service_runtime_podman.plan_podman("x", quadlet)["runtime"],
            "podman-quadlet",
        )

        vm = service_template("vm")
        self.assertEqual(nas_service_runtime_libvirt.plan_libvirt("x", vm)["runtime"], "vm")

        secured = service_template()
        secured["endpoints"] = {
            "web": {
                "transport": "http",
                "targetPort": 8080,
                "exposure": {"type": "path", "value": "/x"},
                "auth": {"mode": "forward-auth"},
            }
        }
        auth_plan = nas_service_authentik.plan_authentik("x", secured)
        self.assertEqual(auth_plan["actions"][0]["type"], "forward-auth")

        secured["network"] = {"lanAccess": False, "allowedEgress": [{"cidr": "10.0.0.0/8", "ports": [443]}]}
        firewall = nas_service_firewall.plan_firewall("x", secured)
        self.assertEqual([action["type"] for action in firewall["actions"]], ["deny-lan", "allow-egress"])

    def test_no_sqlite_dependency(self):
        self.assertNotIn("sqlite3", (SERVICES / "nas_managed_service.py").read_text(encoding="utf-8"))

    def test_atomic_write_and_effective_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pathlib.Path(tmp) / "services.json"
            builtin = pathlib.Path(tmp) / "builtin.json"
            builtin.write_text(
                json.dumps({"schemaVersion": 1, "endpoints": {"builtin:web": {"publicPath": "/builtin"}}}),
                encoding="utf-8",
            )
            service = service_template()
            service["endpoints"] = {
                "web": {
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "hostname", "value": "app.service.local"},
                    "auth": {"mode": "public"},
                }
            }
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, store)
            effective = msvc.effective_registry(builtin, store)
            self.assertIn("builtin:web", effective["endpoints"])
            self.assertTrue(effective["endpoints"]["x:web"]["available"])
            service["enabled"] = False
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, store)
            self.assertFalse(msvc.effective_registry(builtin, store)["endpoints"]["x:web"]["available"])

    def test_write_effective_and_portal_are_atomic_and_cover_projection_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            builtin = root / "builtin.json"
            store = root / "services.json"
            effective_path = root / "run" / "effective.json"
            portal_path = root / "run" / "portal.json"
            builtin.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "endpoints": {
                            "builtin:web": {
                                "label": "Builtin",
                                "publicPath": "/builtin",
                                "linkKey": "console",
                                "access": "admin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            service = service_template()
            service["endpoints"] = {
                "path": visible_endpoint({"type": "path", "value": "/managed"}),
                "host": visible_endpoint({"type": "hostname", "value": "managed.example"}),
                "hidden": {**visible_endpoint({"type": "path", "value": "/hidden"}), "portal": {"visible": False}},
            }
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, store)

            effective = msvc.write_effective(builtin, store, effective_path)
            self.assertEqual(json.loads(effective_path.read_text(encoding="utf-8")), effective)
            self.assertEqual(effective_path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(effective["endpoints"]["builtin:web"]["exposure"]["value"], "/builtin")
            self.assertEqual(effective["endpoints"]["builtin:web"]["portal"]["category"], "Administration")

            portal = msvc.write_portal(effective_path, portal_path)
            self.assertEqual(json.loads(portal_path.read_text(encoding="utf-8")), portal)
            self.assertEqual(portal_path.stat().st_mode & 0o777, 0o644)
            by_id = {entry["id"]: entry for entry in portal["entries"]}
            self.assertEqual(by_id["builtin:web"]["url"], "/builtin")
            self.assertEqual(by_id["x:path"]["url"], "/managed")
            self.assertEqual(by_id["x:host"]["url"], "https://managed.example/")
            self.assertNotIn("x:hidden", by_id)

    def test_read_effective_recomputes_when_runtime_projection_is_missing_or_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "effective.json"
            expected = {"schemaVersion": 2, "generation": 9, "endpoints": {}, "services": {}}
            with mock.patch.object(msvc, "effective_registry", return_value=expected) as recompute:
                self.assertEqual(msvc._read_effective_or_recompute(path), expected)
                path.write_text("{broken", encoding="utf-8")
                self.assertEqual(msvc._read_effective_or_recompute(path), expected)
            self.assertEqual(recompute.call_count, 2)

    def test_portal_projection_port_url_branch(self):
        effective = {
            "schemaVersion": 2,
            "generation": 1,
            "services": {"game": {"label": "Game", "enabled": True}},
            "endpoints": {
                "game:web": {
                    "serviceId": "game",
                    "endpointId": "web",
                    "transport": "http",
                    "targetPort": 25565,
                    "exposure": {"type": "port", "value": 25565},
                    "auth": {"mode": "public"},
                    "portal": {"visible": True},
                    "available": True,
                }
            },
        }
        self.assertEqual(msvc.portal_projection(effective)["entries"][0]["url"], "https://nas.local:25565/")

    def test_load_store_edge_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "missing.json"
            self.assertEqual(msvc.load_store(missing)["services"], {})
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
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service_template()}}, store)
            self.assertIn("x", msvc.effective_registry(builtin, store)["services"])
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {}}, store)
            self.assertNotIn("x", msvc.effective_registry(builtin, store)["services"])

    def test_cli_reconcile_validate_show_and_unimplemented_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            store = root / "services.json"
            builtin = root / "builtin.json"
            effective = root / "effective.json"
            portal = root / "portal.json"
            builtin.write_text(json.dumps({"schemaVersion": 1, "endpoints": {}}), encoding="utf-8")
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {}}, store)

            real_load_store = msvc.load_store
            real_effective_registry = msvc.effective_registry
            real_write_effective = msvc.write_effective
            real_write_portal = msvc.write_portal
            real_write_caddy_fragment = nas_service_caddy.write_caddy_fragment

            def fixture_load_store(*_args, **_kwargs):
                return real_load_store(store)

            def fixture_effective_registry(*_args, **_kwargs):
                return real_effective_registry(builtin, store)

            def fixture_write_effective(*_args, **_kwargs):
                return real_write_effective(builtin, store, effective)

            def fixture_write_portal(*_args, **_kwargs):
                return real_write_portal(effective, portal)

            def fixture_write_caddy_fragment(*_args, **_kwargs):
                return real_write_caddy_fragment(root / "caddy-managed.conf", *_args, **_kwargs)

            with (
                mock.patch.object(msvc, "load_store", side_effect=fixture_load_store),
                mock.patch.object(msvc, "effective_registry", side_effect=fixture_effective_registry),
                mock.patch.object(msvc, "write_effective", side_effect=fixture_write_effective),
                mock.patch.object(msvc, "write_portal", side_effect=fixture_write_portal),
                mock.patch.object(nas_service_caddy, "write_caddy_fragment", side_effect=fixture_write_caddy_fragment),
            ):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(msvc.main(["validate"]), 0)
                    self.assertEqual(msvc.main(["reconcile"]), 0)
                    self.assertEqual(msvc.main(["show", "--json"]), 0)
                self.assertIn("effective", output.getvalue())
                self.assertTrue(effective.is_file())
                self.assertTrue(portal.is_file())
                self.assertTrue((root / "caddy-managed.conf").is_file())
                self.assertEqual(json.loads(effective.read_text(encoding="utf-8"))["services"], {})

                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(msvc.main(["plan"]), 2)
                self.assertIn("not yet implemented", errors.getvalue())

                store.write_text("{bad", encoding="utf-8")
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(msvc.main(["validate"]), 1)
                self.assertIn("Invalid JSON", errors.getvalue())

    def test_caddy_collision_detection(self):
        effective = {
            "schemaVersion": 2,
            "generation": 1,
            "endpoints": {
                "a:web": {
                    "transport": "http",
                    "targetPort": 80,
                    "exposure": {"type": "port", "value": 8080},
                    "auth": {"mode": "public"},
                },
                "b:web": {
                    "transport": "http",
                    "targetPort": 81,
                    "exposure": {"type": "port", "value": 8080},
                    "auth": {"mode": "public"},
                },
            },
        }
        with self.assertRaisesRegex(nas_service_caddy.CaddyError, "Duplicate exposure"):
            nas_service_caddy.generate_caddy_fragment(effective)

        collision = service_template()
        collision["endpoints"] = {
            "web": {
                "transport": "http",
                "targetPort": 80,
                "exposure": {"type": "hostname", "value": "nas.local"},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(msvc.ManagedServiceError, "collides with NAS host"):
            msvc.validate_service("x", collision)


if __name__ == "__main__":
    unittest.main()
