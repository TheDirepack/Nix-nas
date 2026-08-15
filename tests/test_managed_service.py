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

            service = service_template()
            service["endpoints"] = {"web": visible_endpoint({"type": "port", "value": 8443})}
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {"x": service}}, path)
            self.assertEqual(msvc.load_store(path)["services"]["x"]["endpoints"]["web"]["exposure"]["value"], 8443)

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
        vm["resources"] = {"cpus": 0.5}
        with self.assertRaisesRegex(msvc.ManagedServiceError, "CPU count"):
            nas_service_runtime_libvirt._render_domain("x", vm)
        vm["resources"] = {"cpus": 2}
        self.assertIn("<vcpu>2</vcpu>", nas_service_runtime_libvirt._render_domain("x", vm))

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

        firewall_service = service_template()
        firewall_service["endpoints"] = {
            "web": {
                "transport": "tcp",
                "targetPort": 8080,
                "exposure": {"type": "port", "value": 8080},
                "auth": {"mode": "public"},
            }
        }
        firewall_service["network"] = {
            "lanAccess": False,
            "allowedEgress": [{"cidr": "10.0.0.0/8", "ports": [443]}],
        }
        with mock.patch.object(nas_service_firewall.subprocess, "run") as run:
            applied = nas_service_firewall.apply_firewall("x", firewall_service)
            removed = nas_service_firewall.remove_firewall("x", firewall_service)
        self.assertEqual(applied["actions"][-1]["protocol"], "tcp")
        self.assertEqual(len(removed["removed"]), 3)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(any("--add-port=8080/tcp" in command for command in commands))
        self.assertTrue(any("--remove-port=8080/tcp" in command for command in commands))

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

    def test_v2_builtin_registry_is_flattened_for_all_consumers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            builtin = root / "builtin.json"
            store = root / "services.json"
            builtin.write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "generation": 1,
                        "services": {
                            "vaultwarden": {
                                "label": "Vaultwarden",
                                "enabled": False,
                                "endpoints": {
                                    "main": {
                                        "transport": "http",
                                        "targetPort": 8222,
                                        "exposure": {"type": "path", "value": "/vault/", "prefix": True},
                                        "auth": {"mode": "forward-auth", "allow": "groups", "groups": ["vault"]},
                                        "portal": {"visible": True, "linkKey": "vaultwarden"},
                                        "linkKey": "vaultwarden",
                                    }
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            msvc.atomic_write_store({"schemaVersion": 2, "generation": 1, "services": {}}, store)
            effective = msvc.effective_registry(builtin, store)
            endpoint = effective["endpoints"]["vaultwarden:main"]
            self.assertFalse(endpoint["available"])
            self.assertEqual(endpoint["publicPath"], "/vault/")
            self.assertEqual(endpoint["linkKey"], "vaultwarden")
            self.assertEqual(msvc.portal_projection(effective)["entries"][0]["url"], "/vault/")

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

    def test_cli_reconcile_validate_show_and_plan(self):
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

                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(msvc.main(["plan"]), 0)
                self.assertEqual(json.loads(output.getvalue()), {})

                store.write_text("{bad", encoding="utf-8")
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(msvc.main(["validate"]), 1)
                self.assertIn("Invalid JSON", errors.getvalue())

    def test_builtin_registry_and_systemd_edge_cases(self):
        self.assertEqual(
            msvc._builtin_endpoints({"schemaVersion": 1, "endpoints": {"ok": {"publicPath": "/ok"}, "bad": "ignored"}}),
            {"ok": {"publicPath": "/ok"}},
        )
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Unsupported built-in"):
            msvc._builtin_endpoints({"schemaVersion": 99})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "services must be an object"):
            msvc._builtin_endpoints({"schemaVersion": 2, "services": []})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "endpoints must be an object"):
            msvc._builtin_endpoints({"schemaVersion": 2, "services": {"x": {"endpoints": []}}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must be an object"):
            msvc._builtin_endpoints({"schemaVersion": 2, "services": {"x": "bad"}})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "endpoint x:web"):
            msvc._builtin_endpoints({"schemaVersion": 2, "services": {"x": {"endpoints": {"web": []}}}})

        with mock.patch.object(msvc.subprocess, "run", return_value=mock.Mock(returncode=0)):
            self.assertTrue(msvc._systemd_unit_is_active("caddy"))
        with mock.patch.object(msvc.subprocess, "run", return_value=mock.Mock(returncode=1)):
            self.assertFalse(msvc._systemd_unit_is_active("caddy"))
        with mock.patch.object(msvc.subprocess, "run", side_effect=OSError("missing systemctl")):
            self.assertFalse(msvc._systemd_unit_is_active("caddy"))
        with mock.patch.object(msvc.subprocess, "run", side_effect=msvc.subprocess.TimeoutExpired("systemctl", 5)):
            self.assertFalse(msvc._systemd_unit_is_active("caddy"))

    def test_adapter_dispatchers_cover_all_runtime_types(self):
        runtimes = (
            ("compose", nas_service_runtime_compose, "plan_compose", "apply_compose", "remove_compose"),
            ("quadlet", nas_service_runtime_podman, "plan_podman", "apply_podman", "remove_podman"),
            ("vm", nas_service_runtime_libvirt, "plan_libvirt", "apply_libvirt", "remove_libvirt"),
        )
        for runtime_type, module, plan_name, apply_name, remove_name in runtimes:
            service = service_template(runtime_type)
            with (
                mock.patch.object(module, plan_name, return_value={"planned": runtime_type}),
                mock.patch.object(nas_service_authentik, "plan_authentik", return_value={"actions": []}),
                mock.patch.object(nas_service_firewall, "plan_firewall", return_value={"actions": []}),
            ):
                self.assertEqual(msvc._adapter_plan("x", service)["runtime"], {"planned": runtime_type})
            with (
                mock.patch.object(module, apply_name, return_value={"applied": runtime_type}) as apply,
                mock.patch.object(nas_service_authentik, "apply_authentik", return_value={"actions": []}),
                mock.patch.object(nas_service_firewall, "apply_firewall", return_value={"actions": []}),
            ):
                result = msvc._apply_adapters("x", service, dry_run=True)
                self.assertEqual(result["runtime"], {"applied": runtime_type})
                apply.assert_called_once_with("x", service, dry_run=True)
            with (
                mock.patch.object(module, remove_name) as remove,
                mock.patch.object(nas_service_authentik, "remove_authentik"),
                mock.patch.object(nas_service_firewall, "remove_firewall"),
            ):
                msvc._remove_adapters("x", service, dry_run=True)
                if runtime_type == "compose":
                    remove.assert_called_once_with("x", service, dry_run=True)
                else:
                    remove.assert_called_once_with("x", dry_run=True)

        for runtime_type in ("external", "native"):
            service = service_template(runtime_type)
            with (
                mock.patch.object(nas_service_authentik, "plan_authentik", return_value={"actions": []}),
                mock.patch.object(nas_service_firewall, "plan_firewall", return_value={"actions": []}),
            ):
                planned = msvc._adapter_plan("x", service)
            self.assertEqual(planned["runtime"]["runtime"], runtime_type)
            with (
                mock.patch.object(nas_service_authentik, "apply_authentik", return_value={"actions": []}),
                mock.patch.object(nas_service_firewall, "apply_firewall", return_value={"actions": []}),
            ):
                self.assertEqual(msvc._apply_adapters("x", service)["runtime"]["runtime"], runtime_type)
            with (
                mock.patch.object(nas_service_authentik, "remove_authentik"),
                mock.patch.object(nas_service_firewall, "remove_firewall"),
            ):
                msvc._remove_adapters("x", service)

        unsupported = service_template()
        unsupported["runtime"]["type"] = "bad"
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Unsupported runtime"):
            msvc._adapter_plan("x", unsupported)
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Unsupported runtime"):
            msvc._apply_adapters("x", unsupported)
        with self.assertRaisesRegex(msvc.ManagedServiceError, "Unsupported runtime"):
            msvc._remove_adapters("x", unsupported)

    def test_service_input_and_mutation_failures_are_transactional(self):
        service = service_template()
        with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(service))):
            self.assertEqual(msvc._read_json_input(None), service)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "service.json"
            path.write_text(json.dumps(service), encoding="utf-8")
            self.assertEqual(msvc._read_json_input(path), service)
            with self.assertRaisesRegex(msvc.ManagedServiceError, "Unable to read"):
                msvc._read_json_input(path / "missing")
        with mock.patch.object(sys, "stdin", io.StringIO("not-json")):
            with self.assertRaisesRegex(msvc.ManagedServiceError, "not valid JSON"):
                msvc._read_json_input(None)
        with mock.patch.object(sys, "stdin", io.StringIO("[]")):
            with self.assertRaisesRegex(msvc.ManagedServiceError, "must be an object"):
                msvc._read_json_input(None)

        self.assertEqual(msvc._service_from_input("x", {"service": service}), ("x", service))
        self.assertEqual(msvc._service_from_input(None, {"services": {"x": service}}), ("x", service))
        self.assertEqual(msvc._service_from_input(None, {"serviceId": "x", "service": service}), ("x", service))
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must contain an object"):
            msvc._service_from_input("x", {"service": []})
        with self.assertRaisesRegex(msvc.ManagedServiceError, "must include serviceId"):
            msvc._service_from_input(None, {})

        store = {"schemaVersion": 2, "generation": 1, "services": {}}
        with (
            mock.patch.object(msvc, "load_store", return_value=store),
            mock.patch.object(msvc, "_adapter_plan", return_value={"planned": True}),
        ):
            self.assertEqual(msvc._mutate_service("create", "x", service, dry_run=True), {"planned": True})
        with mock.patch.object(msvc, "load_store", return_value={**store, "services": {"x": service}}):
            with self.assertRaisesRegex(msvc.ManagedServiceError, "already exists"):
                msvc._mutate_service("create", "x", service, dry_run=True)
        with mock.patch.object(msvc, "load_store", return_value=store):
            with self.assertRaisesRegex(msvc.ManagedServiceError, "does not exist"):
                msvc._mutate_service("update", "x", service, dry_run=True)

        with (
            mock.patch.object(msvc, "load_store", return_value=store),
            mock.patch.object(msvc, "atomic_write_store"),
            mock.patch.object(msvc, "_apply_adapters", return_value={"applied": True}),
            mock.patch.object(msvc, "_reconcile_runtime", return_value={"projection": True}),
        ):
            result = msvc._mutate_service("create", "x", service, dry_run=False)
            self.assertEqual(result["projection"], {"projection": True})

        for previous, expected in ((None, "Unable to apply"), (service, "adapter rejected")):
            current = {"schemaVersion": 2, "generation": 1, "services": {} if previous is None else {"x": previous}}
            error = (
                RuntimeError("adapter rejected") if previous is None else msvc.ManagedServiceError("adapter rejected")
            )
            with (
                mock.patch.object(msvc, "load_store", return_value=current),
                mock.patch.object(msvc, "atomic_write_store"),
                mock.patch.object(msvc, "_apply_adapters", side_effect=error),
                mock.patch.object(msvc, "_reconcile_runtime", side_effect=RuntimeError("projection failed")),
            ):
                with self.assertRaisesRegex(msvc.ManagedServiceError, expected):
                    msvc._mutate_service("create" if previous is None else "update", "x", service, dry_run=False)

    def test_cli_lifecycle_commands_dispatch_without_shelling_out(self):
        service = service_template()
        store = {"schemaVersion": 2, "generation": 1, "services": {"x": service}}
        with (
            mock.patch.object(msvc, "load_store", return_value=store),
            mock.patch.object(msvc, "_read_json_input", return_value=service),
            mock.patch.object(msvc, "_mutate_service", return_value={"mutated": True}),
            mock.patch.object(msvc, "_adapter_plan", return_value={"planned": True}),
            mock.patch.object(msvc, "_apply_adapters", return_value={"applied": True}),
            mock.patch.object(msvc, "_remove_adapters"),
            mock.patch.object(msvc, "atomic_write_store"),
            mock.patch.object(msvc, "_reconcile_runtime", return_value={"projection": True}),
        ):
            self.assertEqual(msvc.main(["plan", "x"]), 0)
            self.assertEqual(msvc.main(["plan", "x", "--input", "-"]), 0)
            self.assertEqual(msvc.main(["create", "x", "--input", "-"]), 0)
            self.assertEqual(msvc.main(["update", "x", "--input", "-"]), 0)
            self.assertEqual(msvc.main(["adopt", "new", "--input", "-"]), 0)
            self.assertEqual(msvc.main(["import", "x", "--input", "-"]), 0)
            self.assertEqual(msvc.main(["delete", "x", "--dry-run"]), 0)
            self.assertEqual(msvc.main(["delete", "x"]), 0)
            for command in ("start", "stop", "restart"):
                self.assertEqual(msvc.main([command, "x", "--dry-run"]), 0)
            self.assertEqual(msvc.main(["export", "x"]), 0)
            self.assertEqual(msvc.main(["show"]), 0)

        with mock.patch.object(msvc, "load_store", side_effect=OSError("store unavailable")):
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(msvc.main(["validate"]), 1)
            self.assertIn("store unavailable", errors.getvalue())

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
