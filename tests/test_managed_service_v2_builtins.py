from __future__ import annotations

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

import nas_managed_service_v2 as v2  # noqa: E402


def builtin_document() -> dict:
    return {
        "schemaVersion": 2,
        "generation": 3,
        "storageResources": {
            "shares": {
                "path": "/tank/shares",
                "dataset": "tank/shares",
                "scope": "system",
                "stateClass": "authoritative",
                "capabilities": ["read", "write", "move", "delete"],
                "backup": {"enabled": True, "consistency": "zfs-snapshot"},
            }
        },
        "networkProfiles": {},
        "services": {
            "syncthing": {
                "label": "Syncthing administration",
                "enabled": True,
                "ownership": "system",
                "lifecycle": {"mode": "persistent"},
                "runtime": {
                    "type": "systemd",
                    "source": "systemd/syncthing.service",
                    "startPolicy": "boot",
                    "units": ["syncthing.service"],
                },
                "endpoints": {
                    "main": {
                        "transport": "http",
                        "targetPort": 8384,
                        "exposure": {"type": "path", "value": "/syncthing/", "prefix": True},
                        "auth": {
                            "mode": "forward-auth",
                            "capability": "application.syncthing.access",
                            "allow": "groups",
                            "groups": ["nas_admin"],
                        },
                        "portal": {"visible": True, "category": "Files", "icon": "syncthing"},
                    }
                },
            }
        },
    }


def empty_store() -> dict:
    return {
        "schemaVersion": 2,
        "generation": 1,
        "storageResources": {},
        "networkProfiles": {},
        "services": {},
    }


class ManagedServiceV2BuiltinTests(unittest.TestCase):
    def test_builtin_v2_service_and_endpoint_are_visible_in_effective_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            builtin = root / "builtins.json"
            store = root / "services.json"
            builtin.write_text(json.dumps(builtin_document()), encoding="utf-8")
            store.write_text(json.dumps(empty_store()), encoding="utf-8")
            effective = v2.effective_registry(builtin, store)

        service = effective["services"]["syncthing"]
        endpoint = effective["endpoints"]["syncthing:main"]
        self.assertEqual(service["ownership"], "system")
        self.assertEqual(service["principal"], "application:syncthing")
        self.assertEqual(service["lifecycle"], {"mode": "persistent"})
        self.assertEqual(service["runtime"]["type"], "systemd")
        self.assertEqual(endpoint["serviceId"], "syncthing")
        self.assertEqual(endpoint["exposure"]["prefix"], True)
        self.assertEqual(endpoint["auth"]["capability"], "application.syncthing.access")
        self.assertEqual(endpoint["auth"]["groups"], ["nas_admin"])
        self.assertEqual(effective["backupResources"], ["shares"])
        self.assertIn("shares", effective["storageResources"])

    def test_runtime_store_cannot_shadow_builtin_service_or_resource(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            builtin = root / "builtins.json"
            store = root / "services.json"
            builtin.write_text(json.dumps(builtin_document()), encoding="utf-8")

            collision = empty_store()
            collision["services"]["syncthing"] = {
                "label": "Shadow",
                "enabled": False,
                "runtime": {
                    "type": "quadlet",
                    "source": "/var/lib/nas-control/apps/syncthing/app.container",
                    "startPolicy": "disabled",
                },
            }
            store.write_text(json.dumps(collision), encoding="utf-8")
            with self.assertRaisesRegex(Exception, "must not shadow built-in services"):
                v2.effective_registry(builtin, store)

            resource_collision = empty_store()
            resource_collision["storageResources"]["shares"] = builtin_document()["storageResources"]["shares"]
            store.write_text(json.dumps(resource_collision), encoding="utf-8")
            with self.assertRaisesRegex(Exception, "must not shadow built-in resources"):
                v2.effective_registry(builtin, store)

    def test_system_owned_services_are_skipped_by_v2_lifecycle_engine(self) -> None:
        effective = {
            "services": {
                "builtin": {
                    "enabled": True,
                    "ownership": "system",
                    "lifecycle": {"mode": "persistent"},
                    "runtime": {"type": "systemd", "units": ["builtin.service"]},
                },
                "runtime": {
                    "enabled": True,
                    "ownership": "runtime",
                    "lifecycle": {"mode": "persistent"},
                    "runtime": {"type": "quadlet"},
                },
            }
        }
        with mock.patch.object(v2, "_apply_runtime", return_value={"ok": True}) as apply_runtime:
            v2.reconcile_lifecycle(effective)
        apply_runtime.assert_called_once()
        self.assertEqual(apply_runtime.call_args.args[0], "runtime")

    @mock.patch.object(v2.subprocess, "run")
    def test_systemd_runtime_adapter_uses_validated_units(self, run) -> None:
        service = {
            "enabled": True,
            "runtime": {
                "type": "systemd",
                "units": ["alpha.service", "beta.socket"],
            },
        }
        result = v2._apply_runtime("builtin", service, enabled=True)
        self.assertEqual(result["operation"], "start")
        run.assert_called_once_with(["systemctl", "start", "alpha.service", "beta.socket"], check=True)

        run.reset_mock()
        result = v2._apply_runtime("builtin", service, enabled=False)
        self.assertEqual(result["units"], ["beta.socket", "alpha.service"])
        run.assert_called_once_with(["systemctl", "stop", "beta.socket", "alpha.service"], check=True)

    def test_systemd_runtime_rejects_malformed_unit(self) -> None:
        service = {"runtime": {"type": "systemd", "units": ["../escape.service"]}}
        with self.assertRaisesRegex(Exception, "validated units"):
            v2._apply_runtime("builtin", service, enabled=True)


if __name__ == "__main__":
    unittest.main()
