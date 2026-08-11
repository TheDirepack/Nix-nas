from __future__ import annotations

import json
import os
import pathlib
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_doctor as doctor  # noqa: E402


class DoctorCoverageTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_read_json_missing_invalid_and_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            self.assertIsNone(doctor._read_json(root / "missing"))
            invalid = root / "invalid"
            invalid.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError):
                doctor._read_json(invalid)
            sequence = root / "sequence"
            sequence.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "top-level value is not an object"):
                doctor._read_json(sequence)

    def test_version_check_reports_missing_invalid_and_valid(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "VERSION"
            with mock.patch.object(doctor, "VERSION_FILE", path):
                self.assertEqual(doctor._version_check().status, "critical")
                path.write_text("invalid", encoding="utf-8")
                self.assertEqual(doctor._version_check().summary, "Release version is invalid")
                path.write_text("2.2.0-alpha.7", encoding="utf-8")
                self.assertEqual(doctor._version_check().status, "ok")

    def test_setup_checks_cover_journal_and_state_consistency(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state = root / "state.json"
            journal = root / "journal.json"
            first = root / "first.json"
            with (
                mock.patch.object(doctor, "SETUP_STATE", state),
                mock.patch.object(doctor, "SETUP_JOURNAL", journal),
                mock.patch.object(doctor, "FIRST_START_STATUS", first),
            ):
                checks = doctor._setup_checks()
                self.assertTrue(any(check.summary.startswith("Setup state is absent") for check in checks))

                self.write_json(first, {"status": "ready"})
                checks = doctor._setup_checks()
                self.assertTrue(any("Initial setup is not complete" in check.summary for check in checks))

                self.write_json(journal, {"status": "manual-recovery-required", "error": "boundary"})
                self.write_json(state, {"status": "complete", "planDigest": "bad"})
                checks = doctor._setup_checks()
                self.assertTrue(any(check.id == "setup.journal" and check.status == "critical" for check in checks))
                self.assertTrue(any(check.summary == "Completed setup state has no valid plan digest" for check in checks))
                self.assertTrue(any(check.id == "setup.commit-consistency" for check in checks))

                self.write_json(journal, {"status": "failed", "error": "retry"})
                self.write_json(state, {"status": "complete-unverified", "planDigest": "a" * 64})
                checks = doctor._setup_checks()
                self.assertTrue(any(check.id == "setup.journal" and check.status == "warning" for check in checks))
                self.assertTrue(any("without final host preflight" in check.summary for check in checks))

                self.write_json(journal, {"status": "running"})
                self.write_json(state, {"status": "weird"})
                checks = doctor._setup_checks()
                self.assertTrue(any(check.id == "setup.journal" and check.status == "info" for check in checks))
                self.assertTrue(any("invalid completion status" in check.summary for check in checks))

                self.write_json(journal, {"status": "mystery"})
                checks = doctor._setup_checks()
                self.assertTrue(any("unknown status" in check.summary for check in checks))

    def test_managed_services_check_reports_oserror_and_bad_effective_json(self) -> None:
        with mock.patch.object(doctor, "_compile_managed_services", side_effect=OSError("denied")):
            check = doctor._managed_services_check()
        self.assertEqual(check.status, "critical")
        self.assertIn("unreadable", check.summary)

        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "effective.json"
            path.write_text("{", encoding="utf-8")
            with (
                mock.patch.object(doctor, "MANAGED_SERVICES_EFFECTIVE", path),
                mock.patch.object(doctor, "_compile_managed_services", return_value={"generation": 1}),
            ):
                check = doctor._managed_services_check()
        self.assertEqual(check.status, "critical")
        self.assertIn("effective state is unreadable", check.summary)

    def test_platform_path_prefers_runtime_then_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            runtime = root / "runtime.json"
            fallback = root / "fallback.json"
            with (
                mock.patch.object(doctor, "MANAGED_SERVICES_PLATFORM", runtime),
                mock.patch.object(doctor, "MANAGED_SERVICES_PLATFORM_FALLBACK", fallback),
            ):
                self.assertEqual(doctor._managed_services_platform_path(), fallback)
                runtime.write_text("{}", encoding="utf-8")
                self.assertEqual(doctor._managed_services_platform_path(), runtime)

    def test_deep_operation_hygiene_handles_missing_group_and_unsafe_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw) / "ops"
            with mock.patch.object(doctor, "OPERATION_ROOT", root):
                checks = doctor._operation_hygiene_checks(deep=True)
            self.assertEqual(checks[-1].status, "warning")
            self.assertIn("absent", checks[-1].summary)

            root.mkdir()
            with (
                mock.patch.object(doctor, "OPERATION_ROOT", root),
                mock.patch.object(doctor.grp, "getgrnam", side_effect=KeyError("missing")),
            ):
                checks = doctor._operation_hygiene_checks(deep=True)
            self.assertEqual(checks[-1].status, "critical")
            self.assertIn("group is missing", checks[-1].summary)

            metadata = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=2000)
            with (
                mock.patch.object(doctor, "OPERATION_ROOT", root),
                mock.patch.object(pathlib.Path, "lstat", return_value=metadata),
                mock.patch.object(doctor.grp, "getgrnam", return_value=types.SimpleNamespace(gr_gid=3000)),
            ):
                checks = doctor._operation_hygiene_checks(deep=True)
            self.assertEqual(checks[-1].status, "critical")
            self.assertIn("unsafe", checks[-1].summary)

    def test_deep_operation_hygiene_accepts_expected_policy(self) -> None:
        metadata = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o2770, st_uid=0, st_gid=1234)
        with (
            mock.patch.object(pathlib.Path, "lstat", return_value=metadata),
            mock.patch.object(doctor.grp, "getgrnam", return_value=types.SimpleNamespace(gr_gid=1234)),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            checks = doctor._operation_hygiene_checks(deep=True)
        self.assertEqual(checks[-1].status, "ok")

    def test_alert_router_quarantine_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state = pathlib.Path(raw) / "state.json"
            (pathlib.Path(raw) / "state.json.corrupt-1").write_text("bad", encoding="utf-8")
            with mock.patch.object(doctor, "ALERT_ROUTER_STATE", state):
                checks = doctor._alert_router_state_checks()
            self.assertEqual(checks[0].status, "warning")
            self.assertIn("quarantined", checks[0].summary)


if __name__ == "__main__":
    unittest.main()
