from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_spec as spec  # noqa: E402


class V2DisabledDependencyTests(unittest.TestCase):
    def document(self, *, dependent_enabled: bool, dependency_enabled: bool) -> dict:
        return {
            "schemaVersion": 3,
            "services": {
                "backend": {
                    "name": "Backend",
                    "enabled": dependency_enabled,
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "backend.service"},
                },
                "frontend": {
                    "name": "Frontend",
                    "enabled": dependent_enabled,
                    "workload": {"kind": "daemon"},
                    "runtime": {"type": "systemd", "unit": "frontend.service"},
                    "dependencies": [{"service": "backend", "condition": "started"}],
                },
            },
        }

    def test_enabled_service_cannot_depend_on_disabled_service(self) -> None:
        schema = spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
        with self.assertRaises(spec.ManagedServicesV2Error) as raised:
            spec.compile_document(
                self.document(dependent_enabled=True, dependency_enabled=False),
                schema,
            )
        self.assertEqual(raised.exception.code, "dependency-disabled")
        self.assertIn("depends on disabled service 'backend'", str(raised.exception))

    def test_disabled_service_may_retain_disabled_dependency_for_future_reenable(self) -> None:
        schema = spec.load_schema(ROOT / "schemas/managed-services-v3.schema.json")
        effective = spec.compile_document(
            self.document(dependent_enabled=False, dependency_enabled=False),
            schema,
        )
        self.assertFalse(effective["services"]["frontend"]["enabled"])
        self.assertFalse(effective["services"]["backend"]["enabled"])


if __name__ == "__main__":
    unittest.main()
