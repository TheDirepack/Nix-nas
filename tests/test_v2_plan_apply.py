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

import nas_v2_apply as v2apply  # noqa: E402
import nas_v2_plan as v2plan  # noqa: E402
import nas_v2_spec as v2  # noqa: E402


class ManagedServicesV2PlanApplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(SCHEMA)

    def test_plan_contains_only_generic_projection_actions(self):
        document = {
            "schemaVersion": 3,
            "services": {
                "starlight": {
                    "name": "Starlight",
                    "workload": {"kind": "daemon", "activation": "on-demand", "idleSeconds": 600},
                    "runtime": {
                        "type": "exec",
                        "command": ["/run/current-system/sw/bin/starlight", "--serve"],
                    },
                    "readiness": {"probes": [{"type": "tcp", "port": 9000}]},
                    "authorization": {"capabilities": [{"id": "admin", "title": "Administration"}]},
                    "routes": {
                        "web": {
                            "target": {"type": "http", "port": 9000},
                            "exposure": {"type": "path", "paths": ["/starlight/"]},
                            "auth": {"mode": "identity", "capability": "access"},
                            "portal": {"visible": True, "category": "Applications"},
                        }
                    },
                }
            },
        }
        effective = v2.compile_document(document, self.schema)
        plan = v2plan.build_plan(effective)

        self.assertEqual(plan["runtime"][0]["runtimeType"], "exec")
        self.assertIn(
            "application.starlight.access",
            {action["canonicalName"] for action in plan["authentik"]},
        )
        self.assertEqual(plan["caddy"][0]["requiredCapability"], "application.starlight.access")
        self.assertTrue(plan["caddy"][0]["onDemandWake"])
        self.assertEqual(plan["systemd"][0]["action"], "idle-stop")
        self.assertFalse(any("user" in json.dumps(action).lower() for action in plan["authentik"]))
        self.assertFalse(any(action.get("action") == "assign-capability" for action in plan["authentik"]))

    def test_job_schedules_lower_to_systemd_plan(self):
        document = {
            "schemaVersion": 3,
            "services": {
                "verify": {
                    "name": "Verify",
                    "workload": {
                        "kind": "job",
                        "schedules": [
                            {"calendar": "daily", "randomizedDelaySeconds": 900},
                            {"intervalSeconds": 3600},
                        ],
                    },
                    "runtime": {"type": "systemd", "unit": "verify.service"},
                }
            },
        }
        plan = v2plan.build_plan(v2.compile_document(document, self.schema))
        timers = [action for action in plan["systemd"] if action["action"] == "timer"]
        self.assertEqual(len(timers), 2)
        self.assertEqual(timers[0]["schedule"]["randomizedDelaySeconds"], 900)
        self.assertTrue(timers[1]["schedule"]["persistent"])

    def test_save_and_apply_preserves_yaml_comments_and_materializes_derived_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            schema = root / "schema.json"
            schema.write_text(SCHEMA.read_text(encoding="utf-8"), encoding="utf-8")
            platform = root / "platform.json"
            platform.write_text(
                json.dumps({"schemaVersion": 1, "capabilities": {"network-online": True}, "accelerators": {}}),
                encoding="utf-8",
            )
            desired = root / "services.yaml"
            effective = root / "effective.json"
            plan = root / "plan.json"
            paths = v2apply.ApplyPaths(
                desired=desired,
                schema=schema,
                platform=platform,
                effective=effective,
                plan=plan,
            )
            text = """# operator comment
schemaVersion: 3
services:
  demo:
    name: Demo
    workload:
      kind: daemon
      activation: persistent
    runtime:
      type: systemd
      unit: demo.service
"""
            v2apply.save_and_apply(text, paths)
            self.assertEqual(desired.read_text(encoding="utf-8"), text)
            compiled = json.loads(effective.read_text(encoding="utf-8"))
            self.assertEqual(
                compiled["derived"]["authorization"]["demo"]["capabilities"]["access"],
                "application.demo.access",
            )
            self.assertEqual(json.loads(plan.read_text(encoding="utf-8"))["schemaVersion"], 1)

    def test_invalid_save_leaves_previous_authority_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            schema = root / "schema.json"
            schema.write_text(SCHEMA.read_text(encoding="utf-8"), encoding="utf-8")
            desired = root / "services.yaml"
            desired.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            paths = v2apply.ApplyPaths(
                desired=desired,
                schema=schema,
                platform=None,
                effective=root / "effective.json",
                plan=root / "plan.json",
            )
            before = desired.read_bytes()
            with self.assertRaises(v2.ManagedServicesV2Error):
                v2apply.save_and_apply("schemaVersion: 3\nservices:\n  Bad_ID: {}\n", paths)
            self.assertEqual(desired.read_bytes(), before)
            self.assertFalse(paths.effective.exists())
            self.assertFalse(paths.plan.exists())


if __name__ == "__main__":
    unittest.main()
