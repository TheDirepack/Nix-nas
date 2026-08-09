from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_managed_service as legacy
import nas_managed_service_v2 as v2


def service(*, required: list[str] | None = None, capability: str = "application.demo.access") -> dict:
    return {
        "label": "Demo",
        "enabled": True,
        "principal": "application:demo",
        "runtime": {
            "type": "quadlet",
            "source": "/var/lib/nas-control/apps/demo/demo.container",
            "startPolicy": "manual",
        },
        "storage": [
            {
                "resource": "projects",
                "guestPath": "/workspace",
                "requiredCapabilities": required or ["read"],
            }
        ],
        "networkProfile": "restricted-internet",
        "endpoints": {
            "web": {
                "transport": "http",
                "targetPort": 8080,
                "exposure": {"type": "path", "value": "/managed-demo"},
                "auth": {"mode": "forward-auth", "capability": capability},
            }
        },
    }


def document(*, required: list[str] | None = None, capability: str = "application.demo.access") -> dict:
    return {
        "schemaVersion": 2,
        "generation": 1,
        "storageResources": {
            "projects": {
                "path": "/tank/projects",
                "dataset": "tank/projects",
                "scope": "system",
                "stateClass": "authoritative",
                "capabilities": ["read", "write", "move", "delete"],
                "backup": {"enabled": True, "consistency": "zfs-snapshot"},
            },
            "cache": {
                "path": "/tank/cache/demo",
                "scope": "system",
                "stateClass": "cache",
                "capabilities": ["read", "write"],
                "backup": {"enabled": False, "consistency": "none"},
            },
        },
        "networkProfiles": {
            "restricted-internet": {
                "outboundDefault": "allow",
                "lanAccess": False,
            }
        },
        "services": {"demo": service(required=required, capability=capability)},
    }


class ManagedServiceV2Tests(unittest.TestCase):
    def test_normalize_derives_stable_principal_and_read_only_mount(self) -> None:
        data = document(required=["read"])
        del data["services"]["demo"]["principal"]
        normalized = v2.normalize_document(data)
        svc = normalized["services"]["demo"]
        self.assertEqual(svc["principal"], "application:demo")
        self.assertEqual(svc["resolvedStorage"][0]["hostPath"], "/tank/projects")
        self.assertEqual(svc["resolvedStorage"][0]["mode"], "ro")
        self.assertEqual(svc["resolvedStorage"][0]["stateClass"], "authoritative")

    def test_write_capability_derives_rw_mount(self) -> None:
        normalized = v2.normalize_document(document(required=["read", "write"]))
        self.assertEqual(normalized["services"]["demo"]["resolvedStorage"][0]["mode"], "rw")

    def test_legacy_start_policy_migrates_to_lifecycle(self) -> None:
        data = document()
        normalized = v2.normalize_document(data)
        self.assertEqual(
            normalized["services"]["demo"]["lifecycle"],
            {"mode": "manual", "ephemeralRuntime": False},
        )
        data["services"]["demo"]["runtime"]["startPolicy"] = "boot"
        normalized = v2.normalize_document(data)
        self.assertEqual(normalized["services"]["demo"]["lifecycle"]["mode"], "persistent")

    def test_on_demand_lifecycle_requires_idle_timeout(self) -> None:
        data = document()
        data["services"]["demo"]["runtime"]["startPolicy"] = "on-demand"
        data["services"]["demo"]["lifecycle"] = {"mode": "on-demand", "idleSeconds": 900}
        normalized = v2.normalize_document(data)
        self.assertEqual(
            normalized["services"]["demo"]["lifecycle"],
            {"mode": "on-demand", "idleSeconds": 900, "ephemeralRuntime": False},
        )
        del data["services"]["demo"]["lifecycle"]["idleSeconds"]
        with self.assertRaisesRegex(Exception, "requires idleSeconds"):
            v2.normalize_document(data)

    def test_lifecycle_conflicts_fail_closed(self) -> None:
        data = document()
        data["services"]["demo"]["lifecycle"] = {"mode": "disabled"}
        data["services"]["demo"]["runtime"]["startPolicy"] = "disabled"
        with self.assertRaisesRegex(Exception, "enabled=true conflicts"):
            v2.normalize_document(data)

        data = document()
        data["services"]["demo"]["lifecycle"] = {"mode": "persistent"}
        with self.assertRaisesRegex(Exception, "startPolicy=.*conflicts"):
            v2.normalize_document(data)

    def test_capability_must_belong_to_service(self) -> None:
        with self.assertRaisesRegex(Exception, "must start with"):
            v2.normalize_document(document(capability="application.other.access"))

    def test_unknown_network_profile_fails_closed(self) -> None:
        data = document()
        data["services"]["demo"]["networkProfile"] = "missing"
        with self.assertRaisesRegex(Exception, "unknown network profile"):
            v2.normalize_document(data)

    def test_legacy_validation_copy_contains_resolved_mount_only(self) -> None:
        normalized = v2.normalize_document(document(required=["read", "write"]))
        compat = v2._legacy_validation_copy(normalized)
        svc = compat["services"]["demo"]
        self.assertNotIn("principal", svc)
        self.assertNotIn("lifecycle", svc)
        self.assertNotIn("networkProfile", svc)
        self.assertNotIn("resolvedStorage", svc)
        self.assertEqual(
            svc["storage"],
            [
                {
                    "hostPath": "/tank/projects",
                    "guestPath": "/workspace",
                    "mode": "rw",
                    "dataset": "tank/projects",
                }
            ],
        )
        self.assertNotIn("capability", svc["endpoints"]["web"]["auth"])
        legacy.validate_service("demo", svc)

    def test_effective_registry_exposes_resource_backup_and_lifecycle_projection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            store = root / "services.json"
            builtin = root / "builtins.json"
            store.write_text(json.dumps(document(required=["read", "write"])), encoding="utf-8")
            builtin.write_text('{"schemaVersion":1,"endpoints":{}}', encoding="utf-8")
            v2._install_compatibility_layer()
            effective = v2.effective_registry(builtin, store)
            self.assertEqual(effective["backupResources"], ["projects"])
            self.assertEqual(effective["services"]["demo"]["principal"], "application:demo")
            self.assertEqual(effective["services"]["demo"]["lifecycle"]["mode"], "manual")
            self.assertEqual(effective["services"]["demo"]["networkProfile"], "restricted-internet")
            self.assertEqual(effective["services"]["demo"]["resolvedStorage"][0]["mode"], "rw")
            self.assertIn("projects", effective["storageResources"])


if __name__ == "__main__":
    unittest.main()
