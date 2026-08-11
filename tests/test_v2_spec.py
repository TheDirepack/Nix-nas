from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_spec as v2  # noqa: E402


def minimal_service(*, kind: str = "daemon", runtime: dict | None = None) -> dict:
    workload: dict = {"kind": kind}
    if kind == "daemon":
        workload["activation"] = "persistent"
    return {
        "name": "Example",
        "workload": workload,
        "runtime": runtime or {"type": "systemd", "unit": "example.service"},
    }


class ManagedServicesV2SpecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def compile(self, document: dict, capabilities: set[str] | None = None) -> dict:
        return v2.compile_document(document, self.schema, platform_capabilities=capabilities)

    def test_yaml_12_and_duplicate_keys(self):
        parsed = v2.parse_yaml_text("schemaVersion: 3\nservices: {}\nmarker: on\n")
        self.assertEqual(parsed["marker"], "on")

        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "duplicate|found duplicate"):
            v2.parse_yaml_text("schemaVersion: 3\nservices:\n  x:\n    name: X\n    name: Y\n")

    def test_minimal_service_normalizes_and_derives_access_capability(self):
        effective = self.compile({"schemaVersion": 3, "services": {"example": minimal_service()}})
        service = effective["services"]["example"]
        self.assertTrue(service["enabled"])
        self.assertTrue(service["managed"])
        self.assertEqual(service["dependencies"], [])
        self.assertEqual(
            effective["derived"]["authorization"]["example"]["capabilities"]["access"],
            "application.example.access",
        )
        self.assertEqual(effective["derived"]["runtime"]["example"]["ownerUnit"], "example.service")

    def test_native_runtime_inherits_sandbox_by_default(self):
        effective = self.compile({"schemaVersion": 3, "services": {"example": minimal_service()}})
        sandbox = effective["services"]["example"]["sandbox"]
        self.assertEqual(sandbox, {"mode": "inherit"})

    def test_generated_runtime_gets_strict_sandbox_and_dynamic_identity_defaults(self):
        service = minimal_service(
            runtime={
                "type": "exec",
                "command": ["/run/current-system/sw/bin/example"],
                "identity": {"user": "example"},
            }
        )
        effective = self.compile({"schemaVersion": 3, "services": {"example": service}})
        normalized = effective["services"]["example"]
        self.assertEqual(normalized["runtime"]["identity"]["mode"], "dynamic")
        self.assertEqual(normalized["sandbox"]["mode"], "strict")
        self.assertTrue(normalized["sandbox"]["readOnlyRoot"])
        self.assertTrue(normalized["sandbox"]["noNewPrivileges"])

    def test_managed_path_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "root"
            outside = pathlib.Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(v2.ManagedServicesV2Error, "resolves outside"):
                v2._safe_host_path_under(
                    pathlib.PurePosixPath(root.as_posix()),
                    (root / "escape" / "payload").as_posix(),
                    path="$.runtime.source",
                )

    def test_schema_rejects_obsolete_secret_route_auth(self):
        service = minimal_service()
        service["routes"] = {
            "api": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/api/"]},
                "auth": {"mode": "secret"},
            }
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "not one of"):
            self.compile({"schemaVersion": 3, "services": {"example": service}})

    def test_dependency_conditions_and_cycles_fail_closed(self):
        job = minimal_service(kind="job")
        daemon = minimal_service()
        daemon["dependencies"] = [{"service": "job", "condition": "ready"}]
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Jobs cannot satisfy a ready"):
            self.compile({"schemaVersion": 3, "services": {"job": job, "daemon": daemon}})

        left = minimal_service()
        right = minimal_service()
        left["dependencies"] = [{"service": "right", "condition": "started"}]
        right["dependencies"] = [{"service": "left", "condition": "started"}]
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Dependency cycle"):
            self.compile({"schemaVersion": 3, "services": {"left": left, "right": right}})

    def test_ready_dependency_requires_readiness(self):
        backend = minimal_service()
        frontend = minimal_service()
        frontend["dependencies"] = [{"service": "backend", "condition": "ready"}]
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "readiness probes"):
            self.compile({"schemaVersion": 3, "services": {"backend": backend, "frontend": frontend}})

    def test_missing_references_and_platform_capabilities(self):
        service = minimal_service()
        service["storage"] = [{"resource": "missing", "mountPath": "/data"}]
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Unknown storage"):
            self.compile({"schemaVersion": 3, "services": {"example": service}})

        service = minimal_service()
        service["requiresCapabilities"] = ["kvm"]
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Unavailable platform"):
            self.compile({"schemaVersion": 3, "services": {"example": service}}, {"podman"})

    def test_route_and_listener_conflicts_are_rejected(self):
        one = minimal_service()
        two = minimal_service()
        route = {
            "target": {"type": "http", "port": 8080},
            "exposure": {"type": "path", "paths": ["/shared/"]},
            "auth": {"mode": "public"},
        }
        one["routes"] = {"web": route}
        two["routes"] = {"web": route}
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Duplicate route path"):
            self.compile({"schemaVersion": 3, "services": {"one": one, "two": two}})

        one = minimal_service()
        two = minimal_service()
        one["listeners"] = {"sync": {"protocol": "tcp", "exposure": {"start": 22000, "end": 22010}}}
        two["listeners"] = {"other": {"protocol": "tcp", "exposure": {"port": 22005}}}
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "conflicts"):
            self.compile({"schemaVersion": 3, "services": {"one": one, "two": two}})

    def test_identity_route_capability_is_service_scoped(self):
        service = minimal_service()
        service["authorization"] = {"capabilities": [{"id": "admin", "title": "Administration"}]}
        service["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/example/"]},
                "auth": {"mode": "identity", "capability": "admin"},
            }
        }
        effective = self.compile({"schemaVersion": 3, "services": {"example": service}})
        route = effective["derived"]["routes"][0]
        self.assertEqual(route["requiredCapability"], "application.example.admin")

        bad = minimal_service()
        bad["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8080},
                "exposure": {"type": "path", "paths": ["/example/"]},
                "auth": {"mode": "identity", "capability": "admin"},
            }
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "undeclared"):
            self.compile({"schemaVersion": 3, "services": {"example": bad}})

    def test_gpu_rules_are_runtime_neutral_and_vm_passthrough_is_explicit(self):
        vm = minimal_service(runtime={"type": "vm", "source": "/var/lib/nas-control/apps/vm/domain.xml"})
        vm["resources"] = {"accelerators": [{"kind": "gpu", "mode": "passthrough", "device": "pci:0000:03:00.0"}]}
        self.compile({"schemaVersion": 3, "services": {"vm": vm}})

        unsafe = minimal_service(runtime={"type": "vm", "source": "/var/lib/nas-control/apps/vm/domain.xml"})
        unsafe["resources"] = {"accelerators": [{"kind": "gpu", "mode": "passthrough"}]}
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "explicit pci"):
            self.compile({"schemaVersion": 3, "services": {"vm": unsafe}})

    def test_compose_inner_targets_are_explicit(self):
        service = minimal_service(runtime={"type": "compose", "source": "/var/lib/nas-control/apps/app/compose.yaml"})
        service["storage"] = [{"resource": "data", "mountPath": "/data"}]
        document = {
            "schemaVersion": 3,
            "storageResources": {
                "data": {
                    "path": "/tank/data",
                    "stateClass": "authoritative",
                }
            },
            "services": {"app": service},
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "explicit target"):
            self.compile(document)

    def test_cache_and_ephemeral_storage_cannot_be_authoritative_backup(self):
        document = {
            "schemaVersion": 3,
            "storageResources": {
                "cache": {
                    "path": "/tank/cache",
                    "stateClass": "cache",
                    "backup": {"enabled": True, "consistency": "filesystem"},
                }
            },
            "services": {},
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Cache/ephemeral"):
            self.compile(document)

    def test_credentials_are_references_under_runtime_secret_root(self):
        good = {
            "schemaVersion": 3,
            "credentials": {"env": {"path": "/run/nas-secrets/app/env"}},
            "services": {},
        }
        self.compile(good)

        bad = {
            "schemaVersion": 3,
            "credentials": {"env": {"path": "/etc/shadow"}},
            "services": {},
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "beneath /run/nas-secrets"):
            self.compile(bad)


if __name__ == "__main__":
    unittest.main()
