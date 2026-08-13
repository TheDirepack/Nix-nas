from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_doctor  # noqa: E402
from nas_state import Authority  # noqa: E402


class DoctorTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def test_managed_services_check_reports_reconciled_authority(self) -> None:
        expected = {"schemaVersion": 3, "generation": 4, "services": {"core": {}}}
        with tempfile.TemporaryDirectory() as temporary:
            effective = pathlib.Path(temporary) / "effective.json"
            self.write_json(effective, expected)
            with (
                mock.patch.object(nas_doctor, "MANAGED_SERVICES_EFFECTIVE", effective),
                mock.patch.object(nas_doctor, "_compile_managed_services", return_value=expected),
            ):
                check = nas_doctor._managed_services_check()
        self.assertEqual("ok", check.status)
        self.assertIn("1 services", check.summary)

    def test_managed_services_check_detects_effective_drift(self) -> None:
        expected = {"schemaVersion": 3, "generation": 4, "services": {"core": {"enabled": True}}}
        with tempfile.TemporaryDirectory() as temporary:
            effective = pathlib.Path(temporary) / "effective.json"
            self.write_json(effective, {**expected, "generation": 3})
            with (
                mock.patch.object(nas_doctor, "MANAGED_SERVICES_EFFECTIVE", effective),
                mock.patch.object(nas_doctor, "_compile_managed_services", return_value=expected),
            ):
                check = nas_doctor._managed_services_check()
        self.assertEqual("critical", check.status)
        self.assertIn("does not match services.yaml", check.summary)
        self.assertIn("desiredGeneration=4", check.detail or "")

    def test_managed_services_check_reports_invalid_desired_state(self) -> None:
        with mock.patch.object(
            nas_doctor,
            "_compile_managed_services",
            side_effect=nas_doctor.ManagedServicesDiagnosticError("missing platform capability: podman"),
        ):
            check = nas_doctor._managed_services_check()
        self.assertEqual("critical", check.status)
        self.assertIn("desired state is invalid", check.summary)
        self.assertIn("missing platform capability: podman", check.detail or "")
        self.assertIn("services.yaml", check.remediation or "")

    def test_managed_services_check_reports_missing_effective_state(self) -> None:
        expected = {"schemaVersion": 3, "generation": 7, "services": {}}
        with tempfile.TemporaryDirectory() as temporary:
            effective = pathlib.Path(temporary) / "missing-effective.json"
            with (
                mock.patch.object(nas_doctor, "MANAGED_SERVICES_EFFECTIVE", effective),
                mock.patch.object(nas_doctor, "_compile_managed_services", return_value=expected),
            ):
                check = nas_doctor._managed_services_check()
        self.assertEqual("warning", check.status)
        self.assertIn("effective state is absent", check.summary)
        self.assertEqual(str(effective), check.detail)
        self.assertIn("reconcile", check.remediation or "")

    def test_unified_report_is_healthy_without_legacy_migration_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            version = root / "VERSION"
            version.write_text("2.1.0-alpha.22\n", encoding="utf-8")
            state_authority = root / "authority"
            state_authority.mkdir()
            setup_state = root / "setup-state.json"
            setup_journal = root / "setup-journal.json"
            first_start = root / "first-start.json"
            digest = "a" * 64
            self.write_json(setup_state, {"schemaVersion": 2, "status": "complete", "planDigest": digest})
            self.write_json(setup_journal, {"schemaVersion": 1, "status": "complete"})
            self.write_json(first_start, {"schemaVersion": 2, "status": "complete", "planDigest": digest})
            patches = (
                mock.patch.object(nas_doctor, "VERSION_FILE", version),
                mock.patch.object(nas_doctor, "SETUP_STATE", setup_state),
                mock.patch.object(nas_doctor, "SETUP_JOURNAL", setup_journal),
                mock.patch.object(nas_doctor, "FIRST_START_STATUS", first_start),
                mock.patch.object(
                    nas_doctor,
                    "_managed_services_check",
                    return_value=nas_doctor.Check(
                        "runtime.managed-services", "ok", "Managed Services V2 is reconciled"
                    ),
                ),
                mock.patch.object(nas_doctor, "authorities", return_value=(Authority("test", str(state_authority)),)),
                mock.patch.object(nas_doctor, "operation_state", return_value={"busyClasses": [], "active": []}),
            )
            with __import__("contextlib").ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                report = nas_doctor.build_report()
            self.assertEqual("healthy", report["status"])
            self.assertNotIn("migrations", report)
            self.assertTrue(any(item["id"] == "state.registry" for item in report["checks"]))
            self.assertTrue(any(item["id"] == "runtime.managed-services" for item in report["checks"]))

    def test_human_report_surfaces_summary_and_remediation(self) -> None:
        payload = {
            "status": "degraded",
            "summary": {"ok": 2, "warning": 1, "critical": 0, "info": 1},
            "checks": [
                {
                    "id": "setup.state",
                    "status": "warning",
                    "summary": "Setup needs attention",
                    "detail": "final preflight was skipped",
                    "remediation": "Run the complete preflight",
                }
            ],
        }
        rendered = nas_doctor._human(payload)
        self.assertIn("Checks: 2 ok, 1 warning, 0 critical, 1 info", rendered)
        self.assertIn("Next: Run the complete preflight", rendered)

    def test_doctor_warns_about_coordination_environment_contamination(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "NAS_OPERATION_COORDINATED": "1",
                nas_doctor.COORDINATION_TOKEN_ENV: "forged-token",
            },
            clear=False,
        ):
            checks = nas_doctor._operation_hygiene_checks(deep=False)
        by_id = {item.id: item for item in checks}
        self.assertEqual("warning", by_id["operations.legacy-environment"].status)
        self.assertEqual("warning", by_id["operations.inherited-token"].status)


if __name__ == "__main__":
    unittest.main()
