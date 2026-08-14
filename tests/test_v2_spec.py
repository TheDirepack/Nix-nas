from __future__ import annotations

import json
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

    def test_prefix_overlapping_route_paths_are_rejected(self):
        # Parent/child paths are allowed only when longest-path-first ordering is guaranteed
        parent = minimal_service()
        parent["routes"] = {
            "api": {
                "target": {"type": "http", "port": 8081},
                "exposure": {"type": "path", "paths": ["/api"]},
                "auth": {"mode": "public"},
            }
        }
        child = minimal_service()
        child["routes"] = {
            "users": {
                "target": {"type": "http", "port": 8082},
                "exposure": {"type": "path", "paths": ["/api/users"]},
                "auth": {"mode": "public"},
            }
        }
        # Allowed parent/child – renderer sorts longest first
        self.compile({"schemaVersion": 3, "services": {"parent": parent, "child": child}})

        # Exact duplicate paths must still fail closed
        dup_a = minimal_service()
        dup_a["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8081},
                "exposure": {"type": "path", "paths": ["/api"]},
                "auth": {"mode": "public"},
            }
        }
        dup_b = minimal_service()
        dup_b["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8082},
                "exposure": {"type": "path", "paths": ["/api"]},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Duplicate route path"):
            self.compile({"schemaVersion": 3, "services": {"a": dup_a, "b": dup_b}})

        # Normalized duplicate (/api vs /api/) must also fail closed
        slash_a = minimal_service()
        slash_a["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8081},
                "exposure": {"type": "path", "paths": ["/api/"]},
                "auth": {"mode": "public"},
            }
        }
        slash_b = minimal_service()
        slash_b["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8082},
                "exposure": {"type": "path", "paths": ["/api"]},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "Duplicate route path"):
            self.compile({"schemaVersion": 3, "services": {"a": slash_a, "b": slash_b}})

        # Root "/" shadowing everything is ambiguous and must still fail closed
        root = minimal_service()
        root["routes"] = {
            "catchall": {
                "target": {"type": "http", "port": 8083},
                "exposure": {"type": "path", "paths": ["/"]},
                "auth": {"mode": "public"},
            }
        }
        other = minimal_service()
        other["routes"] = {
            "specific": {
                "target": {"type": "http", "port": 8084},
                "exposure": {"type": "path", "paths": ["/anything"]},
                "auth": {"mode": "public"},
            }
        }
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "overlaps"):
            self.compile({"schemaVersion": 3, "services": {"root": root, "other": other}})

        sibling = minimal_service()
        sibling["routes"] = {
            "one": {
                "target": {"type": "http", "port": 8085},
                "exposure": {"type": "path", "paths": ["/api/v1"]},
                "auth": {"mode": "public"},
            }
        }
        sibling2 = minimal_service()
        sibling2["routes"] = {
            "two": {
                "target": {"type": "http", "port": 8086},
                "exposure": {"type": "path", "paths": ["/api/v2"]},
                "auth": {"mode": "public"},
            }
        }
        self.compile({"schemaVersion": 3, "services": {"one": sibling, "two": sibling2}})

    def test_real_seed_overlapping_routes_compile(self):
        # Real seed uses parent/child routes: /shares with /shares/admin,
        # /vault with /vault/admin, and /ai/ with /ai/v1 and /ai/runtime.
        # These must compile when longest-path-first ordering is guaranteed.
        copyparty = minimal_service()
        copyparty["authorization"] = {"capabilities": [{"id": "files", "title": "Files"}, {"id": "admin", "title": "Admin"}]}
        copyparty["routes"] = {
            "files": {
                "target": {"type": "http", "port": 8000},
                "exposure": {"type": "path", "paths": ["/shares"]},
                "auth": {"mode": "identity", "capability": "files"},
            },
            "admin": {
                "target": {"type": "http", "port": 8000},
                "exposure": {"type": "path", "paths": ["/shares/admin"]},
                "auth": {"mode": "identity", "capability": "admin"},
            },
        }
        vault = minimal_service()
        vault["authorization"] = {"capabilities": [{"id": "access", "title": "Access"}, {"id": "admin", "title": "Admin"}]}
        vault["routes"] = {
            "web": {
                "target": {"type": "http", "port": 8001},
                "exposure": {"type": "path", "paths": ["/vault"]},
                "auth": {"mode": "upstream"},
            },
            "admin": {
                "target": {"type": "http", "port": 8001},
                "exposure": {"type": "path", "paths": ["/vault/admin"]},
                "auth": {"mode": "identity", "capability": "admin"},
            },
        }
        ai_runtime = minimal_service()
        ai_runtime["routes"] = {
            "admin": {
                "target": {"type": "http", "port": 8002},
                "exposure": {"type": "path", "paths": ["/ai/runtime"]},
                "auth": {"mode": "identity", "capability": "access"},
            },
            "api": {
                "target": {"type": "http", "port": 8002},
                "exposure": {"type": "path", "paths": ["/ai/v1"]},
                "auth": {"mode": "upstream"},
            },
        }
        ai_workspace = minimal_service()
        ai_workspace["routes"] = {
            "main": {
                "target": {"type": "http", "port": 8003},
                "exposure": {"type": "path", "paths": ["/ai/"]},
                "auth": {"mode": "identity", "capability": "access"},
            },
        }
        doc = {
            "schemaVersion": 3,
            "services": {
                "copyparty": copyparty,
                "vaultwarden": vault,
                "ai-runtime": ai_runtime,
                "ai-workspace": ai_workspace,
            },
        }
        effective = self.compile(doc)
        # Verify derived routes contain all 7 paths
        paths = set()
        for route in effective["derived"]["routes"]:
            for p in route["exposure"].get("paths", []):
                paths.add(p)
        for expected in ("/shares", "/shares/admin", "/vault", "/vault/admin", "/ai/", "/ai/v1", "/ai/runtime"):
            self.assertIn(expected, paths)

    def test_systemd_runtime_unit_must_be_a_safe_unit_name(self):
        good = minimal_service()
        self.compile({"schemaVersion": 3, "services": {"example": good}})
        for unit in ("foo.service", "nas-v2-foo.target", "timer@1.service"):
            service = minimal_service(runtime={"type": "systemd", "unit": unit})
            self.compile({"schemaVersion": 3, "services": {"example": service}})
        for unit in ("bad unit.service", "evil\n.service", "no-suffix", ".service", "x.unknown"):
            service = minimal_service(runtime={"type": "systemd", "unit": unit})
            with self.assertRaisesRegex(v2.ManagedServicesV2Error, "runtime unit"):
                self.compile({"schemaVersion": 3, "services": {"example": service}})

    def test_paths_reject_all_control_characters(self):
        service = minimal_service()
        service["storage"] = [{"resource": "data", "mountPath": "/data"}]
        parent = {
            "schemaVersion": 3,
            "storageResources": {"data": {"path": "/srv/data", "stateClass": "authoritative"}},
            "services": {"example": service},
        }
        for bad in ("/srv/tab\tpath", "/srv/esc\x1b", "/srv/del\x7f"):
            mutated = json.loads(json.dumps(parent))
            mutated["storageResources"]["data"]["path"] = bad
            with self.assertRaisesRegex(v2.ManagedServicesV2Error, "control character"):
                self.compile(mutated)

    def test_session_workload_defaults_to_isolated_deny_network(self):
        service = minimal_service()
        service["workload"] = {"kind": "session"}
        effective = self.compile({"schemaVersion": 3, "services": {"example": service}})
        network = effective["services"]["example"]["network"]
        self.assertEqual(network["mode"], "isolated")
        self.assertEqual(network["outboundDefault"], "deny")

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

    def test_empty_authority_parsing_fails_closed(self):
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "must not be empty"):
            v2.parse_yaml_text("", source="<test>")
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "must not be empty"):
            v2.parse_yaml_text("   \n\t\n", source="<test>")
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "must not be empty"):
            v2.parse_yaml_text("null\n", source="<test>")
        with self.assertRaises(v2.ManagedServicesV2Error):
            v2.parse_yaml_text("null", source="<test>")

    def test_root_not_mapping_fails(self):
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "mapping/object"):
            v2.parse_yaml_text("[]\n", source="<test>")
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "mapping/object"):
            v2.parse_yaml_text("42\n", source="<test>")
        with self.assertRaisesRegex(v2.ManagedServicesV2Error, "mapping/object"):
            v2.parse_yaml_text('"hello"\n', source="<test>")

    def test_empty_mapping_fails_schema_but_valid_empty_services_succeeds(self):
        with self.assertRaises(v2.ManagedServicesV2Error):
            self.compile({})
        valid = v2.parse_yaml_text("schemaVersion: 3\nservices: {}\n", source="<test>")
        self.assertEqual(valid, {"schemaVersion": 3, "services": {}})
        effective = self.compile({"schemaVersion": 3, "services": {}})
        self.assertEqual(effective["services"], {})

    def test_truncated_authority_leaves_previous_effective_untouched(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            spec = tmp_path / "services.yaml"
            schema = SCHEMA
            effective = tmp_path / "effective.json"
            plan = tmp_path / "plan.json"
            # initial valid generation A
            spec.write_text(
                "schemaVersion: 3\nservices:\n  example:\n    name: Example\n    workload:\n      kind: daemon\n    runtime:\n      type: systemd\n      unit: example.service\n",
                encoding="utf-8",
            )
            from nas_v2_apply import ApplyPaths, compile_paths
            import nas_v2_apply as apply_mod

            paths = ApplyPaths(
                desired=spec,
                schema=schema,
                platform=None,
                effective=effective,
                plan=plan,
            )
            eff_a, _ = compile_paths(paths)
            # write effective manually to simulate successful reconcile
            effective.write_text(json.dumps(eff_a, sort_keys=True), encoding="utf-8")
            plan.write_text(json.dumps({"generation": 1}, sort_keys=True), encoding="utf-8")
            previous_eff = effective.read_text(encoding="utf-8")
            previous_plan = plan.read_text(encoding="utf-8")
            # truncate authority
            spec.write_text("", encoding="utf-8")
            with self.assertRaises(v2.ManagedServicesV2Error):
                compile_paths(paths)
            # ensure apply also fails without mutating effective/plan (transactional compile)
            try:
                apply_mod.apply(paths)
                self.fail("apply should have raised on truncated authority")
            except v2.ManagedServicesV2Error:
                pass
            self.assertEqual(effective.read_text(encoding="utf-8"), previous_eff)
            self.assertEqual(plan.read_text(encoding="utf-8"), previous_plan)


if __name__ == "__main__":
    unittest.main()
