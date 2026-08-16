from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest
import sys
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_common
from repo_test_utils import text


class CapabilityRegistryTests(unittest.TestCase):
    def test_generated_registry_is_exported_and_schema_backed(self) -> None:
        internal = text("modules/nas/internal/default.nix")
        system = text("modules/nas/config/system.nix")
        registry = text("modules/nas/internal/service-registry.nix")
        validator = text("scripts/validate-repository-data.py")
        self.assertIn("common // core_registry", internal)
        self.assertIn('"nas-control/capabilities.json"', system)
        self.assertIn('"nas-control/capability-registry.schema.json"', system)
        self.assertIn('"nas-control/endpoints.json".text = builtins.toJSON nasInternal.serviceRegistryV2', system)
        self.assertIn("serviceRegistryV2 =", registry)
        self.assertIn("services = registry", registry)
        self.assertIn('"schemas/capability-registry.schema.json"', validator)

    def test_caddy_capabilities_fail_closed(self) -> None:
        caddy = text("modules/nas/internal/caddy-helpers.nix")
        self.assertIn("Unknown NAS capability referenced by a Caddy route", caddy)
        self.assertIn("lib.attrByPath", caddy)
        self.assertNotIn("nas_allow_files", caddy)

    def test_caddy_gate_uses_trusted_authentik_identity(self) -> None:
        caddy = text("modules/nas/internal/caddy-helpers.nix")
        for expected in (
            "request_header Remote-User {http.request.header.X-Authentik-Username}",
            "request_header Remote-Groups {http.request.header.X-Authentik-Groups}",
            "request_header Remote-Name {http.request.header.X-Authentik-Name}",
            "request_header Remote-Email {http.request.header.X-Authentik-Email}",
            "request_header Remote-UID {http.request.header.X-Authentik-Uid}",
            "header_up Remote-User {http.request.header.X-Authentik-Username}",
            "header_up Remote-Groups {http.request.header.X-Authentik-Groups}",
            "header_up Remote-Name {http.request.header.X-Authentik-Name}",
            "header_up Remote-Email {http.request.header.X-Authentik-Email}",
            "header_up Remote-UID {http.request.header.X-Authentik-Uid}",
        ):
            self.assertIn(expected, caddy)
        self.assertIn("not header X-Authentik-Username *", caddy)
        self.assertIn(
            "copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Entitlements",
            caddy,
        )
        self.assertNotIn("not header Remote-User *", caddy)
        self.assertNotIn("X-Authentik-Groups>Remote-Groups", caddy)

    def test_runtime_loader_accepts_a_generated_shape(self) -> None:
        value = {
            "schemaVersion": 1,
            "identityGroups": {
                "administrator": "admins",
                "user": "users",
                "guest": "guests",
                "disabled": "disabled",
            },
            "capabilities": {
                "example": {
                    "id": "example",
                    "allowGroup": "nas_allow_example",
                    "denyGroup": "nas_deny_example",
                    "administratorBypass": False,
                    "description": "Test capability",
                    "owner": "test-service",
                    "routes": ["/test/"],
                    "canWakeService": False,
                    "exposedInSetup": True,
                    "exposedInCockpit": True,
                    "authentikClaims": ["groups"],
                    "available": True,
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "capabilities.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": str(path)}):
                groups, capabilities = nas_common._load_capability_registry()
        self.assertEqual(groups["administrator"], "admins")
        self.assertEqual(capabilities["example"]["denyGroup"], "nas_deny_example")

    def test_runtime_loader_rejects_mismatched_ids(self) -> None:
        value = {
            "schemaVersion": 1,
            "identityGroups": {
                "administrator": "admins",
                "user": "users",
                "guest": "guests",
                "disabled": "disabled",
            },
            "capabilities": {
                "example": {
                    "id": "different",
                    "allowGroup": "nas_allow_example",
                    "denyGroup": "nas_deny_example",
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "capabilities.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": str(path)}):
                with self.assertRaisesRegex(RuntimeError, "Invalid capability"):
                    nas_common._load_capability_registry()

    def test_runtime_loader_rejects_duplicate_capability_groups(self) -> None:
        value = {
            "schemaVersion": 1,
            "identityGroups": {
                "administrator": "admins",
                "user": "users",
                "guest": "guests",
                "disabled": "disabled",
            },
            "capabilities": {
                "first": {
                    "id": "first",
                    "allowGroup": "nas_allow_shared",
                    "denyGroup": "nas_deny_first",
                    "administratorBypass": True,
                    "description": "Test capability",
                    "owner": "test-service",
                    "routes": ["/test/"],
                    "canWakeService": False,
                    "exposedInSetup": True,
                    "exposedInCockpit": True,
                    "authentikClaims": ["groups"],
                    "available": True,
                },
                "second": {
                    "id": "second",
                    "allowGroup": "nas_allow_shared",
                    "denyGroup": "nas_deny_second",
                    "administratorBypass": True,
                    "description": "Test capability",
                    "owner": "test-service",
                    "routes": ["/test/"],
                    "canWakeService": False,
                    "exposedInSetup": True,
                    "exposedInCockpit": True,
                    "authentikClaims": ["groups"],
                    "available": True,
                },
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "capabilities.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_CAPABILITY_REGISTRY_FILE": str(path)}):
                with self.assertRaisesRegex(RuntimeError, "Invalid capability"):
                    nas_common._load_capability_registry()


if __name__ == "__main__":
    unittest.main()
