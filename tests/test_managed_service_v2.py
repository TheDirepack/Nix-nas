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

import nas_managed_network as managed_network  # noqa: E402
import nas_managed_service as legacy  # noqa: E402
import nas_managed_service_v2 as v2  # noqa: E402


def service(
    *,
    required: list[str] | None = None,
    capability: str = "application.demo.access",
    target: str | None = None,
) -> dict:
    attachment = {
        "resource": "projects",
        "guestPath": "/workspace",
        "requiredCapabilities": required or ["read"],
    }
    if target is not None:
        attachment["target"] = target
    return {
        "label": "Demo",
        "enabled": True,
        "principal": "application:demo",
        "runtime": {
            "type": "quadlet",
            "source": "/var/lib/nas-control/apps/demo/demo.container",
            "startPolicy": "manual",
        },
        "storage": [attachment],
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


def document(
    *,
    required: list[str] | None = None,
    capability: str = "application.demo.access",
    target: str | None = None,
) -> dict:
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
                "allowedHostPorts": [9292],
            }
        },
        "services": {"demo": service(required=required, capability=capability, target=target)},
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

    def test_write_capability_derives_rw_mount_and_preserves_target(self) -> None:
        normalized = v2.normalize_document(document(required=["read", "write"], target="web"))
        mount = normalized["services"]["demo"]["resolvedStorage"][0]
        self.assertEqual(mount["mode"], "rw")
        self.assertEqual(mount["target"], "web")

    def test_named_network_profile_resolves_to_service_identity(self) -> None:
        normalized = v2.normalize_document(document())
        resolved = normalized["services"]["demo"]["resolvedNetwork"]
        self.assertEqual(resolved["identity"], managed_network.service_network("demo"))
        self.assertFalse(resolved["lanAccess"])
        self.assertEqual(resolved["outboundDefault"], "allow")
        self.assertEqual(resolved["allowedHostPorts"], [9292])

    def test_inline_network_override_merges_with_named_profile(self) -> None:
        data = document()
        data["services"]["demo"]["network"] = {"outboundDefault": "deny"}
        resolved = v2.normalize_document(data)["services"]["demo"]["resolvedNetwork"]
        self.assertEqual(resolved["outboundDefault"], "deny")
        self.assertFalse(resolved["lanAccess"])
        self.assertEqual(resolved["allowedHostPorts"], [9292])

    def test_invalid_network_policy_fails_closed(self) -> None:
        data = document()
        data["networkProfiles"]["restricted-internet"]["allowedHostPorts"] = [0]
        with self.assertRaisesRegex(Exception, "invalid port"):
            v2.normalize_document(data)

    def test_legacy_start_policy_migrates_to_lifecycle(self) -> None:
        data = document()
        normalized = v2.normalize_document(data)
        self.assertEqual(normalized["services"]["demo"]["lifecycle"], {"mode": "session"})
        data["services"]["demo"]["runtime"]["startPolicy"] = "boot"
        normalized = v2.normalize_document(data)
        self.assertEqual(normalized["services"]["demo"]["lifecycle"], {"mode": "persistent"})
        data["services"]["demo"]["runtime"]["startPolicy"] = "on-demand"
        normalized = v2.normalize_document(data)
        self.assertEqual(
            normalized["services"]["demo"]["lifecycle"],
            {"mode": "on-demand", "idleSeconds": v2.DEFAULT_IDLE_SECONDS},
        )

    def test_disabled_is_availability_not_a_lifecycle_mode(self) -> None:
        data = document()
        data["services"]["demo"]["enabled"] = False
        data["services"]["demo"]["runtime"]["startPolicy"] = "disabled"
        normalized = v2.normalize_document(data)
        self.assertFalse(normalized["services"]["demo"]["enabled"])
        self.assertEqual(normalized["services"]["demo"]["lifecycle"], {"mode": "persistent"})
        data["services"]["demo"]["enabled"] = True
        with self.assertRaisesRegex(Exception, "requires enabled=false"):
            v2.normalize_document(data)

    def test_on_demand_lifecycle_requires_idle_timeout(self) -> None:
        data = document()
        data["services"]["demo"]["runtime"]["startPolicy"] = "on-demand"
        data["services"]["demo"]["lifecycle"] = {"mode": "on-demand", "idleSeconds": 900}
        normalized = v2.normalize_document(data)
        self.assertEqual(normalized["services"]["demo"]["lifecycle"], {"mode": "on-demand", "idleSeconds": 900})
        del data["services"]["demo"]["lifecycle"]["idleSeconds"]
        with self.assertRaisesRegex(Exception, "requires idleSeconds"):
            v2.normalize_document(data)

    def test_session_and_persistent_reject_idle_timeout(self) -> None:
        for mode, start_policy in (("persistent", "boot"), ("session", "manual")):
            data = document()
            data["services"]["demo"]["runtime"]["startPolicy"] = start_policy
            data["services"]["demo"]["lifecycle"] = {"mode": mode, "idleSeconds": 60}
            with self.subTest(mode=mode), self.assertRaisesRegex(Exception, "only valid for on-demand"):
                v2.normalize_document(data)

    def test_lifecycle_conflicts_fail_closed(self) -> None:
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

    def test_legacy_validation_copy_strips_v2_projection_fields(self) -> None:
        normalized = v2.normalize_document(document(required=["read", "write"], target="web"))
        compat = v2._legacy_validation_copy(normalized)
        svc = compat["services"]["demo"]
        for key in ("principal", "lifecycle", "networkProfile", "resolvedStorage", "resolvedNetwork"):
            self.assertNotIn(key, svc)
        self.assertEqual(
            svc["storage"],
            [{"hostPath": "/tank/projects", "guestPath": "/workspace", "mode": "rw", "dataset": "tank/projects"}],
        )
        self.assertNotIn("capability", svc["endpoints"]["web"]["auth"])
        legacy.validate_service("demo", svc)

    def test_effective_registry_exposes_resource_backup_lifecycle_and_network_projection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            store = root / "services.json"
            builtin = root / "builtins.json"
            store.write_text(json.dumps(document(required=["read", "write"], target="web")), encoding="utf-8")
            builtin.write_text('{"schemaVersion":1,"endpoints":{}}', encoding="utf-8")
            v2._install_compatibility_layer()
            effective = v2.effective_registry(builtin, store)
            svc = effective["services"]["demo"]
            self.assertEqual(effective["backupResources"], ["projects"])
            self.assertEqual(svc["principal"], "application:demo")
            self.assertEqual(svc["lifecycle"]["mode"], "session")
            self.assertEqual(svc["networkProfile"], "restricted-internet")
            self.assertEqual(svc["resolvedNetwork"]["identity"], managed_network.service_network("demo"))
            self.assertEqual(svc["resolvedStorage"][0]["mode"], "rw")
            self.assertEqual(svc["resolvedStorage"][0]["target"], "web")
            self.assertIn("projects", effective["storageResources"])

    def test_reconcile_enforces_persistent_and_stops_disabled_or_session(self) -> None:
        effective = {
            "services": {
                "always": {"enabled": True, "lifecycle": {"mode": "persistent"}},
                "sleepy": {"enabled": True, "lifecycle": {"mode": "on-demand", "idleSeconds": 300}},
                "session": {"enabled": True, "lifecycle": {"mode": "session"}},
                "off": {"enabled": False, "lifecycle": {"mode": "persistent"}},
            }
        }
        with mock.patch.object(v2, "_apply_runtime", return_value={"ok": True}) as apply_runtime:
            result = v2.reconcile_lifecycle(effective)
        calls = {(call.args[0], call.kwargs["enabled"]) for call in apply_runtime.call_args_list}
        self.assertEqual(calls, {("always", True), ("session", False), ("off", False)})
        self.assertEqual(len(result["actions"]), 3)

    def test_generic_start_rejects_session_runtime(self) -> None:
        effective = {"services": {"demo": {"enabled": True, "lifecycle": {"mode": "session"}}}}
        with mock.patch.object(v2, "effective_registry", return_value=effective):
            with self.assertRaisesRegex(Exception, "session launcher"):
                v2.start_service("demo")


if __name__ == "__main__":
    unittest.main()
