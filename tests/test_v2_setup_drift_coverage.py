from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_setup as setup  # noqa: E402
from nas_operation_journal import JournalError  # noqa: E402


class SetupDriftCoverageTests(unittest.TestCase):
    def test_existing_account_success_missing_and_error_shapes(self) -> None:
        with mock.patch.object(
            setup, "run_root", return_value=setup.Completed((), '{"username":"alice"}', "", 0)
        ):
            self.assertEqual(setup.existing_account("alice"), {"username": "alice"})
        with mock.patch.object(setup, "run_root", return_value=setup.Completed((), "[]", "", 0)):
            with self.assertRaisesRegex(setup.SetupError, "invalid exported account"):
                setup.existing_account("alice")
        with mock.patch.object(setup, "run_root", return_value=setup.Completed((), "{", "", 0)):
            with self.assertRaisesRegex(setup.SetupError, "invalid exported account JSON"):
                setup.existing_account("alice")
        with mock.patch.object(
            setup, "run_root", return_value=setup.Completed((), "", "account does not exist", 1)
        ):
            self.assertIsNone(setup.existing_account("alice"))
        with mock.patch.object(setup, "run_root", return_value=setup.Completed((), "", "denied", 2)):
            with self.assertRaisesRegex(setup.SetupError, "Unable to inspect"):
                setup.existing_account("alice")

    def test_setup_authority_health_defers_runtime_authorities_until_secrets_ready(self) -> None:
        config = {"accounts": [], "services": {"demo": "always"}}
        with (
            mock.patch.object(setup, "keepass_database_ready", return_value=True),
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup, "dataset_exists", return_value=True),
            mock.patch.object(setup, "share_directories_ready", return_value=True),
            mock.patch.object(pathlib.Path, "is_file", return_value=False),
            mock.patch.object(setup, "identity_command_ready") as identity,
            mock.patch.object(setup, "service_policy_ready") as services,
        ):
            result = setup.setup_authority_health(config)
        self.assertTrue(result["ok"])
        self.assertIsNone(result["checks"]["identity"])
        identity.assert_not_called()
        services.assert_not_called()

    def test_setup_authority_health_includes_runtime_authorities_when_ready(self) -> None:
        config = {"accounts": [], "services": {"demo": "always"}}
        with (
            mock.patch.object(setup, "keepass_database_ready", return_value=True),
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup, "dataset_exists", return_value=True),
            mock.patch.object(setup, "share_directories_ready", return_value=True),
            mock.patch.object(pathlib.Path, "is_file", return_value=True),
            mock.patch.object(setup, "identity_command_ready", return_value=True),
            mock.patch.object(setup, "service_policy_ready", return_value=False),
        ):
            result = setup.setup_authority_health(config)
        self.assertFalse(result["ok"])
        self.assertTrue(result["checks"]["identity"])
        self.assertFalse(result["checks"]["managedServices"])

    def test_first_start_status_handles_invalid_state_and_missing_config(self) -> None:
        with mock.patch.object(setup, "load_json", side_effect=JournalError("broken")):
            result = setup.first_start_status("/missing")
        self.assertEqual(result["status"], "state-invalid")
        with mock.patch.object(setup, "load_json", return_value=None):
            result = setup.first_start_status("/definitely/missing/first-run.json")
        self.assertEqual(result["status"], "configuration-missing")

    def test_first_start_status_handles_invalid_changed_drift_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "first.json"
            path.write_text("{}", encoding="utf-8")
            normalized = {
                "storage": {"createPool": False, "devices": [], "topology": "single", "wipeDevices": False, "ashift": 12},
                "accounts": [],
                "services": {},
                "runPreflight": True,
            }
            with (
                mock.patch.object(setup, "load_json", return_value=None),
                mock.patch.object(setup, "read_json_source", return_value={}),
                mock.patch.object(setup, "normalize_config", side_effect=setup.SetupError("bad config")),
            ):
                self.assertEqual(setup.first_start_status(str(path))["status"], "configuration-invalid")

            with (
                mock.patch.object(setup, "load_json", return_value={"status": "complete", "planDigest": "old"}),
                mock.patch.object(setup, "read_json_source", return_value={}),
                mock.patch.object(setup, "normalize_config", return_value=normalized),
                mock.patch.object(setup, "validate_service_request"),
                mock.patch.object(setup, "setup_plan_digest", return_value="new"),
            ):
                self.assertEqual(setup.first_start_status(str(path))["status"], "configuration-changed")

            state = {"status": "complete", "planDigest": "same", "completedAt": "now"}
            with (
                mock.patch.object(setup, "load_json", return_value=state),
                mock.patch.object(setup, "read_json_source", return_value={}),
                mock.patch.object(setup, "normalize_config", return_value=normalized),
                mock.patch.object(setup, "validate_service_request"),
                mock.patch.object(setup, "setup_plan_digest", return_value="same"),
                mock.patch.object(setup, "setup_authority_health", return_value={"ok": False, "checks": {}}),
            ):
                self.assertEqual(setup.first_start_status(str(path))["status"], "state-drift")

            with (
                mock.patch.object(setup, "load_json", return_value=state),
                mock.patch.object(setup, "read_json_source", return_value={}),
                mock.patch.object(setup, "normalize_config", return_value=normalized),
                mock.patch.object(setup, "validate_service_request"),
                mock.patch.object(setup, "setup_plan_digest", return_value="same"),
                mock.patch.object(setup, "setup_authority_health", return_value={"ok": True, "checks": {}}),
            ):
                result = setup.first_start_status(str(path))
            self.assertEqual(result["status"], "complete")
            self.assertIn("complete", result["message"])

    def test_first_start_status_ready_reports_destructive_storage_plan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "first.json"
            path.write_text("{}", encoding="utf-8")
            normalized = {
                "storage": {
                    "createPool": True,
                    "devices": ["/dev/a", "/dev/b"],
                    "topology": "mirror",
                    "wipeDevices": True,
                    "ashift": 13,
                },
                "accounts": [{"username": "alice"}],
                "services": {"demo": "always"},
                "runPreflight": False,
            }
            with (
                mock.patch.object(setup, "load_json", return_value=None),
                mock.patch.object(setup, "read_json_source", return_value={}),
                mock.patch.object(setup, "normalize_config", return_value=normalized),
                mock.patch.object(setup, "validate_service_request"),
                mock.patch.object(setup, "setup_plan_digest", return_value="a" * 64),
                mock.patch.object(setup, "pool_exists", return_value=False),
            ):
                result = setup.first_start_status(str(path))
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["requiresDestructiveConfirmation"])
        self.assertEqual(result["storage"]["topology"], "mirror")
        self.assertEqual(result["accountCount"], 1)
        self.assertEqual(result["serviceCount"], 1)

    def test_status_report_runtime_authorities_fail_closed_on_command_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state = root / "state.json"
            journal = root / "journal.json"
            first = root / "first.json"
            state.write_text('{"status":"complete"}', encoding="utf-8")
            results = [
                setup.Completed((), "", "denied", 1),
                setup.Completed((), "{", "", 0),
            ]
            with (
                mock.patch.object(setup, "STATE_PATH", state),
                mock.patch.object(setup, "JOURNAL_PATH", journal),
                mock.patch.object(setup, "FIRST_START_STATUS_PATH", first),
                mock.patch.object(setup, "KEEPASS_DATABASE", root / "db"),
                mock.patch.object(pathlib.Path, "exists", return_value=True),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "dataset_exists", return_value=True),
                mock.patch.object(setup, "load_json", return_value=None),
                mock.patch.object(setup, "run_root_noninteractive", side_effect=results),
            ):
                report = setup.status_report()
        self.assertIn("error", report["identity"])
        self.assertEqual(report["managedServices"], {"error": "invalid JSON"})

    def test_status_report_accepts_runtime_authority_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with (
                mock.patch.object(setup, "STATE_PATH", root / "missing-state"),
                mock.patch.object(setup, "JOURNAL_PATH", root / "missing-journal"),
                mock.patch.object(setup, "FIRST_START_STATUS_PATH", root / "missing-first"),
                mock.patch.object(setup, "KEEPASS_DATABASE", root / "db"),
                mock.patch.object(pathlib.Path, "exists", return_value=True),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "dataset_exists", return_value=True),
                mock.patch.object(setup, "load_json", return_value=None),
                mock.patch.object(
                    setup,
                    "run_root_noninteractive",
                    side_effect=[
                        setup.Completed((), '{"ok":true}', "", 0),
                        setup.Completed((), '{"services":[]}', "", 0),
                    ],
                ),
            ):
                report = setup.status_report()
        self.assertTrue(report["identity"]["ok"])
        self.assertEqual(report["managedServices"]["services"], [])


if __name__ == "__main__":
    unittest.main()
