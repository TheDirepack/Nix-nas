from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_control as control  # noqa: E402
import nas_v2_apply as v2apply  # noqa: E402
import nas_v2_editor as editor  # noqa: E402
import nas_v2_spec as v2spec  # noqa: E402

SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"

SPEC = importlib.util.spec_from_file_location("nas_cockpit_api_ws07", SERVICES / "nas_cockpit_api.py")  # noqa: E402
assert SPEC and SPEC.loader
api = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = api
SPEC.loader.exec_module(api)


def write_services_yaml(path: pathlib.Path, content: str = "") -> pathlib.Path:
    path.write_text(content, encoding="utf-8")
    return path


def valid_desired_text() -> str:
    return (
        "schemaVersion: 3\n"
        "services:\n"
        "  demo:\n"
        "    name: Demo\n"
        "    workload:\n"
        "      kind: daemon\n"
        "      activation: persistent\n"
        "    runtime:\n"
        "      type: systemd\n"
        "      unit: demo.service\n"
        "  backup:\n"
        "    name: Backup\n"
        "    workload:\n"
        "      kind: job\n"
        "      schedules:\n"
        "        - calendar: daily\n"
        "    runtime:\n"
        "      type: systemd\n"
        "      unit: backup.service\n"
    )


def valid_effective_content(desired_text: str | None = None) -> dict:
    text = desired_text or valid_desired_text()
    desired_bytes = text.encode("utf-8")
    effective = v2spec.compile_document(
        v2spec.parse_yaml_text(text, source="<test>"),
        v2spec.load_schema(SCHEMA),
    )
    effective["provenance"] = {"desiredSha256": hashlib.sha256(desired_bytes).hexdigest()}
    return effective


class Ws07EffectiveStateTests(unittest.TestCase):
    def test_missing_effective_leaves_desired_visible_but_reports_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text(valid_desired_text(), encoding="utf-8")
            missing = root / "missing-effective.json"
            status = editor.status(desired_path=desired, effective_path=missing)
            by_id = {row["id"]: row for row in status["services"]}
            self.assertEqual(by_id["demo"]["requestedMode"], "always")
            # Effective availability must be unknown/false, not borrowed from desired
            self.assertFalse(by_id["demo"]["effective"])
            self.assertFalse(by_id["demo"]["available"])
            self.assertFalse(by_id["demo"]["runtimeAvailable"])
            self.assertIsNone(by_id["demo"]["effectiveMode"])
            # Same for backup job
            self.assertFalse(by_id["backup"]["effective"])

    def test_malformed_effective_cannot_produce_verified_badge(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text(valid_desired_text(), encoding="utf-8")
            malformed = root / "effective.json"
            malformed.write_text("{ not json", encoding="utf-8")
            status = editor.status(desired_path=desired, effective_path=malformed)
            for row in status["services"]:
                self.assertFalse(row["effective"])
                self.assertFalse(row["available"])
                self.assertIsNone(row["effectiveMode"])

    def test_incomplete_effective_cannot_produce_verified_badge(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text(valid_desired_text(), encoding="utf-8")
            incomplete = root / "effective.json"
            incomplete.write_text(
                json.dumps(
                    {
                        "schemaVersion": 3,
                        "provenance": valid_effective_content()["provenance"],
                        "services": {"demo": valid_effective_content()["services"]["demo"]},
                        "derived": {
                            "runtime": {"demo": {"ownerUnit": "demo.service", "type": "systemd", "managed": True}}
                        },
                    }
                ),
                encoding="utf-8",
            )
            status = editor.status(desired_path=desired, effective_path=incomplete)
            by_id = {row["id"]: row for row in status["services"]}
            # demo present but backup missing -> backup not verified
            self.assertFalse(by_id["backup"]["effective"])
            self.assertIsNone(by_id["backup"]["effectiveMode"])
            # demo may be verified if present, but we test missing service case
            # Also test incomplete workload
            incomplete2 = root / "effective2.json"
            incomplete2.write_text(
                json.dumps(
                    {
                        "schemaVersion": 3,
                        "provenance": valid_effective_content()["provenance"],
                        "services": {
                            "demo": {"enabled": True},
                            "backup": valid_effective_content()["services"]["backup"],
                        },
                        "derived": valid_effective_content()["derived"],
                    }
                ),
                encoding="utf-8",
            )
            status2 = editor.status(desired_path=desired, effective_path=incomplete2)
            by_id2 = {row["id"]: row for row in status2["services"]}
            self.assertFalse(by_id2["demo"]["effective"])

    def test_equal_mtime_revision_mismatch_cannot_produce_verified_badge(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text(valid_desired_text(), encoding="utf-8")
            stale = root / "effective.json"
            stale.write_text(json.dumps(valid_effective_content()), encoding="utf-8")
            desired.write_text("# exact bytes changed\n" + valid_desired_text(), encoding="utf-8")
            timestamp = 1_800_000_000
            desired.touch()
            stale.touch()
            os.utime(desired, (timestamp, timestamp))
            os.utime(stale, (timestamp, timestamp))
            status = editor.status(desired_path=desired, effective_path=stale)
            by_id = {row["id"]: row for row in status["services"]}
            self.assertFalse(by_id["demo"]["effective"])
            self.assertIsNone(by_id["demo"]["effectiveMode"])

    def test_missing_provenance_rejects_otherwise_valid_effective(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = write_services_yaml(root / "services.yaml", valid_desired_text())
            value = valid_effective_content()
            del value["provenance"]
            effective = root / "effective.json"
            effective.write_text(json.dumps(value), encoding="utf-8")

            result = editor.status(desired_path=desired, effective_path=effective)

            self.assertTrue(all(not row["verified"] for row in result["services"]))
            self.assertTrue(all(row["units"] == [] for row in result["services"]))

    def test_forged_runtime_or_workload_is_not_admitted(self) -> None:
        for field, forged in (
            ("runtime", {"type": "systemd", "unit": "forged.service"}),
            ("workload", {"kind": "job", "schedules": []}),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as raw:
                root = pathlib.Path(raw)
                desired = write_services_yaml(root / "services.yaml", valid_desired_text())
                value = valid_effective_content()
                value["services"]["demo"][field] = forged
                effective = root / "effective.json"
                effective.write_text(json.dumps(value), encoding="utf-8")

                result = editor.status(desired_path=desired, effective_path=effective)
                demo = next(row for row in result["services"] if row["id"] == "demo")

                self.assertFalse(demo["verified"])
                self.assertEqual(demo["units"], [])

    def test_missing_derived_runtime_fields_are_not_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = write_services_yaml(root / "services.yaml", valid_desired_text())
            value = valid_effective_content()
            del value["derived"]["runtime"]["demo"]["ownerUnit"]
            effective = root / "effective.json"
            effective.write_text(json.dumps(value), encoding="utf-8")

            result = editor.status(desired_path=desired, effective_path=effective)
            demo = next(row for row in result["services"] if row["id"] == "demo")

            self.assertFalse(demo["verified"])
            self.assertEqual(demo["units"], [])

    def test_apply_publishes_exact_desired_provenance_in_effective_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = write_services_yaml(root / "services.yaml", valid_desired_text())
            paths = v2apply.ApplyPaths(
                desired=desired,
                schema=SCHEMA,
                platform=None,
                effective=root / "effective.json",
                plan=root / "plan.json",
            )

            v2apply.apply(paths)

            expected = hashlib.sha256(desired.read_bytes()).hexdigest()
            effective = json.loads(paths.effective.read_text(encoding="utf-8"))
            plan = json.loads(paths.plan.read_text(encoding="utf-8"))
            self.assertEqual(effective["provenance"], {"desiredSha256": expected})
            self.assertEqual(plan["provenance"], effective["provenance"])

    def test_unverified_jobs_cannot_be_launched(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text(valid_desired_text(), encoding="utf-8")
            missing = root / "missing.json"
            status = editor.status(desired_path=desired, effective_path=missing)
            # Simulate cockpit_api managed_job_rows filtering
            with mock.patch.object(api, "managed_services_status", return_value=status):
                rows = api.managed_job_rows()
                self.assertEqual(rows, [], "Unverified jobs must not be launchable when effective missing")
            # Also via control status -> operations should not allow
            with (
                mock.patch.object(control, "desired_status", return_value=status),
                mock.patch.object(control, "_unit_snapshot", return_value={}),
            ):
                result = control.status()
                backup_row = next(r for r in result["services"] if r["id"] == "backup")
                self.assertFalse(backup_row["effective"])
                self.assertFalse(backup_row["available"])

    def test_valid_compiled_availability_and_live_activity_remain_separate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text(valid_desired_text(), encoding="utf-8")
            effective = root / "effective.json"
            effective.write_text(json.dumps(valid_effective_content()), encoding="utf-8")
            status = editor.status(desired_path=desired, effective_path=effective)
            by_id = {row["id"]: row for row in status["services"]}
            self.assertTrue(by_id["demo"]["effective"])
            self.assertTrue(by_id["demo"]["available"])
            self.assertTrue(by_id["demo"]["runtimeAvailable"])
            self.assertEqual(by_id["demo"]["effectiveMode"], "always")
            # Now via control.status with live snapshot inactive
            with (
                mock.patch.object(control, "desired_status", return_value=status),
                mock.patch.object(
                    control,
                    "_unit_snapshot",
                    return_value={
                        "demo.service": {"ActiveState": "inactive", "SubState": "dead", "MemoryCurrent": "[not set]"},
                        "backup.service": {"ActiveState": "inactive", "SubState": "dead", "MemoryCurrent": "[not set]"},
                    },
                ),
            ):
                result = control.status()
                demo = next(r for r in result["services"] if r["id"] == "demo")
                # Compiled availability remains true even though live is inactive
                self.assertTrue(demo["effective"])
                self.assertTrue(demo["available"])
                self.assertFalse(demo["running"])
                self.assertEqual(demo["healthState"], "inactive")
                # Now active
            with (
                mock.patch.object(control, "desired_status", return_value=status),
                mock.patch.object(
                    control,
                    "_unit_snapshot",
                    return_value={
                        "demo.service": {"ActiveState": "active", "SubState": "running", "MemoryCurrent": "1000"},
                        "backup.service": {"ActiveState": "active", "SubState": "running", "MemoryCurrent": "1000"},
                    },
                ),
            ):
                result2 = control.status()
                demo2 = next(r for r in result2["services"] if r["id"] == "demo")
                self.assertTrue(demo2["running"])
                self.assertEqual(demo2["healthState"], "healthy")

    def test_valid_effective_continues_to_report_accurate_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            desired = root / "services.yaml"
            desired.write_text(valid_desired_text(), encoding="utf-8")
            effective = root / "effective.json"
            effective.write_text(json.dumps(valid_effective_content()), encoding="utf-8")
            status = editor.status(desired_path=desired, effective_path=effective)
            # Simulate cockpit_api service_states merging
            with (
                mock.patch.object(api, "managed_services_status", return_value=status),
                mock.patch.object(
                    api,
                    "service_states",
                    return_value={"demo.service": {"activeState": "active", "subState": "running"}},
                ),
            ):
                # managed_job_rows should now include backup when verified
                rows = api.managed_job_rows()
                self.assertTrue(any(r["id"] == "backup" for r in rows))
