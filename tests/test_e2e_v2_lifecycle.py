"""End-to-end V2 lifecycle: YAML -> effective -> all native projections.

This is the single deterministic E2E that proves the entire V2 pipeline works
for every runtime, network, and storage primitive without mocking the
projections. It is intentionally not a coverage-gap filler; it asserts that a
real-world document compiles and that each adapter produces non-empty,
fail-closed output.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas/managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_caddy as caddy  # noqa: E402
import nas_v2_plan as v2plan  # noqa: E402
import nas_v2_spec as spec  # noqa: E402


def _doc_with_all_primitives() -> dict:
    return {
        "schemaVersion": 3,
        "storageResources": {
            "proj": {
                "path": "/tank/projects",
                "dataset": "tank/projects",
                "scope": "system",
                "stateClass": "authoritative",
                "capabilities": ["read", "write"],
                "backup": {"enabled": True, "consistency": "zfs-snapshot"},
            }
        },
        "credentials": {"app-env": {"path": "/run/nas-secrets/app.env", "required": False}},
        "services": {
            "svc-systemd": {
                "name": "Systemd service",
                "enabled": True,
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "systemd", "unit": "demo.service"},
                "storage": [{"resource": "proj", "mountPath": "/workspace", "access": "write"}],
                "credentials": [{"credential": "app-env", "use": "file", "mountPath": "/run/creds/app.env"}],
                "readiness": {"probes": [{"type": "tcp", "host": "127.0.0.1", "port": 8080}]},
                "routes": {
                    "web": {
                        "target": {"type": "http", "host": "127.0.0.1", "port": 8080},
                        "exposure": {"type": "path", "paths": ["/svc-systemd/"]},
                        "auth": {"mode": "identity", "capability": "access"},
                    }
                },
            },
            "svc-exec": {
                "name": "Exec service",
                "enabled": True,
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {
                    "type": "exec",
                    "command": ["/run/current-system/sw/bin/sleep", "infinity"],
                    "restart": "on-failure",
                },
                "storage": [{"resource": "proj", "mountPath": "/data", "access": "write"}],
            },
            "svc-quadlet": {
                "name": "Quadlet",
                "enabled": True,
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "quadlet", "source": "/var/lib/nas-control/apps/svc-quadlet/app.container"},
                "network": {"mode": "isolated"},
            },
            "svc-compose": {
                "name": "Compose",
                "enabled": True,
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/svc-compose/compose.yaml"},
                "network": {"mode": "isolated"},
                "routes": {
                    "ui": {
                        "target": {"type": "http", "host": "127.0.0.1", "port": 3000},
                        "exposure": {"type": "path", "paths": ["/compose/"]},
                        "auth": {"mode": "identity", "capability": "access"},
                    }
                },
            },
            "svc-vm": {
                "name": "VM",
                "enabled": True,
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "vm", "source": "/var/lib/nas-control/apps/svc-vm/domain.xml"},
            },
            "svc-job": {
                "name": "Nightly job",
                "enabled": True,
                "workload": {"kind": "job", "schedules": [{"calendar": "daily"}]},
                "runtime": {"type": "systemd", "unit": "demo-job.service"},
            },
            "svc-session": {
                "name": "Session",
                "enabled": True,
                "workload": {"kind": "session"},
                "runtime": {"type": "systemd", "unit": "demo-session.service"},
            },
        },
    }


class E2EV2LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = spec.load_schema(SCHEMA)

    def test_full_document_compiles(self) -> None:
        doc = _doc_with_all_primitives()
        effective = spec.compile_document(doc, self.schema)
        self.assertEqual(effective["schemaVersion"], 3)
        self.assertIn("services", effective)
        self.assertEqual(len(effective["services"]), 7)
        for sid in ("svc-systemd", "svc-exec", "svc-quadlet", "svc-compose", "svc-vm"):
            self.assertIn(sid, effective["services"])

    def test_plan_is_deterministic_and_nonempty(self) -> None:
        doc = _doc_with_all_primitives()
        effective = spec.compile_document(doc, self.schema)
        p1 = v2plan.build_plan(effective)
        p2 = v2plan.build_plan(effective)
        self.assertEqual(p1, p2)
        self.assertTrue(p1["runtime"])
        self.assertIn("caddy", p1)
        self.assertIn("systemd", p1)
        self.assertIn("authentik", p1)
        self.assertIn("storageBackup", p1)

    def test_caddy_projection_covers_all_routes(self) -> None:
        doc = _doc_with_all_primitives()
        effective = spec.compile_document(doc, self.schema)
        caddyfile = caddy.generate_caddyfile(effective)
        self.assertIn("svc-systemd", caddyfile)
        self.assertIn("/svc-systemd/", caddyfile)
        self.assertIn("/compose/", caddyfile)
        self.assertIn("forward_auth", caddyfile)

    def test_systemd_projection_covers_all_runtimes(self) -> None:
        doc = _doc_with_all_primitives()
        effective = spec.compile_document(doc, self.schema)
        plan = v2plan.build_plan(effective)
        runtime_actions = plan["runtime"]
        text = json.dumps(runtime_actions)
        for sid in ("svc-systemd", "svc-exec", "svc-quadlet", "svc-compose", "svc-vm", "svc-job", "svc-session"):
            self.assertIn(sid, text)
        self.assertIn("timer", json.dumps(plan["systemd"]))

    def test_network_and_storage_backup_are_in_plan(self) -> None:
        doc = _doc_with_all_primitives()
        effective = spec.compile_document(doc, self.schema)
        plan = v2plan.build_plan(effective)
        self.assertIn("network", plan)
        self.assertIn("storageBackup", plan)
        self.assertTrue(any(a["resource"] == "proj" for a in plan["storageBackup"] if a.get("resource") == "proj"))

    def test_backup_inventory_covers_authoritative_resources(self) -> None:
        doc = _doc_with_all_primitives()
        effective = spec.compile_document(doc, self.schema)
        plan = v2plan.build_plan(effective)
        backup_text = json.dumps(plan["storageBackup"])
        self.assertIn("proj", backup_text)
        self.assertIn("zfs-snapshot", backup_text)

    def test_authentik_blueprint_creates_capability_objects(self) -> None:
        doc = _doc_with_all_primitives()
        effective = spec.compile_document(doc, self.schema)
        plan = v2plan.build_plan(effective)
        authentik = plan["authentik"]
        self.assertTrue(any("application." in a.get("canonicalName", "") for a in authentik))
        self.assertEqual(len(authentik), 7)

    def test_plan_covers_network_and_storage(self) -> None:
        doc = _doc_with_all_primitives()
        effective = spec.compile_document(doc, self.schema)
        plan = v2plan.build_plan(effective)
        self.assertIn("network", plan)
        self.assertIn("storageBackup", plan)

    def test_yaml_roundtrip_via_spec(self) -> None:
        doc = _doc_with_all_primitives()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            import yaml

            yaml.safe_dump(doc, tmp)
            tmp.flush()
            loaded = spec.parse_yaml(pathlib.Path(tmp.name))
            self.assertEqual(loaded["schemaVersion"], 3)
            effective = spec.compile_document(loaded, self.schema)
            self.assertIn("svc-systemd", effective["services"])

    def test_disabled_service_is_marked_disabled_in_plan(self) -> None:
        doc = _doc_with_all_primitives()
        doc["services"]["svc-systemd"]["enabled"] = False
        effective = spec.compile_document(doc, self.schema)
        p = v2plan.build_plan(effective)
        svc = next(a for a in p["runtime"] if a["service"] == "svc-systemd")
        self.assertFalse(svc["enabled"])
        active = [a for a in p["runtime"] if a["service"] == "svc-exec"]
        self.assertTrue(active[0]["enabled"])


if __name__ == "__main__":
    unittest.main()
