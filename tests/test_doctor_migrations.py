from __future__ import annotations

import contextlib
import json
import os
import pathlib
import tempfile
import unittest
import sys
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_doctor
import nas_migrate_state
from nas_migrate_state import MigrationItem, PlannedMigration
from nas_state import Authority


class MigrationTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, value: object, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        path.chmod(mode)

    def test_feature_boolean_state_has_explicit_safe_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            catalog = root / "features.json"
            state = root / "settings.json"
            self.write_json(
                catalog,
                {
                    "schemaVersion": 2,
                    "features": {
                        "ai": {
                            "allowedModes": ["off", "on-demand", "always"],
                            "defaultMode": "off",
                            "legacyTrueMode": "on-demand",
                        },
                        "backup": {"allowedModes": ["off", "always"], "defaultMode": "always"},
                    },
                },
            )
            self.write_json(state, {"schemaVersion": 1, "features": {"ai": True, "backup": False}})
            plan = nas_migrate_state.plan_feature_state(state, catalog)
            self.assertEqual("migration-required", plan.item.status)
            self.assertIsNotNone(plan.value)
            assert plan.value is not None
            self.assertEqual(2, plan.value["schemaVersion"])
            self.assertEqual({"ai": "on-demand", "backup": "off"}, plan.value["features"])

    def test_unknown_legacy_feature_is_never_silently_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            catalog = root / "features.json"
            state = root / "settings.json"
            self.write_json(catalog, {"schemaVersion": 2, "features": {"known": {"allowedModes": ["off", "always"]}}})
            self.write_json(state, {"schemaVersion": 1, "features": {"unknown": True}})
            with self.assertRaisesRegex(nas_migrate_state.MigrationError, "unknown feature"):
                nas_migrate_state.plan_feature_state(state, catalog)

    def test_apply_creates_private_backup_before_atomic_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "settings.json"
            self.write_json(state, {"schemaVersion": 1, "features": {"ai": True}}, mode=0o640)
            plan = PlannedMigration(
                MigrationItem("feature-control", str(state), "migration-required", 1, 2, "test"),
                {"schemaVersion": 2, "features": {"ai": "on-demand"}, "updatedAt": 1},
                0o640,
            )
            with (
                mock.patch.object(nas_migrate_state, "MIGRATION_ROOT", root / "backups"),
                mock.patch.object(nas_migrate_state, "acquire_operation", return_value=contextlib.nullcontext()),
                mock.patch.dict(os.environ, {"NAS_MIGRATE_ALLOW_UNPRIVILEGED": "1"}),
            ):
                report = nas_migrate_state.apply_all([plan])
            self.assertEqual("complete", report["status"])
            self.assertEqual(2, json.loads(state.read_text())["schemaVersion"])
            self.assertEqual(0o640, state.stat().st_mode & 0o777)
            backup = pathlib.Path(report["items"][0]["backup"])
            self.assertTrue(backup.is_file())
            self.assertEqual(0o600, backup.stat().st_mode & 0o777)
            self.assertEqual(1, json.loads(backup.read_text())["schemaVersion"])

    def test_unknown_setup_schema_requires_manual_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "state.json"
            self.write_json(path, {"schemaVersion": 99, "status": "complete"})
            plan = nas_migrate_state.plan_setup_state(path)
            self.assertEqual("unsupported", plan.item.status)


class DoctorTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def test_unified_report_is_healthy_for_consistent_authorities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            version = root / "VERSION"
            version.write_text("2.1.0-alpha.22\n", encoding="utf-8")
            state_authority = root / "authority"
            state_authority.mkdir()
            catalog = root / "features.json"
            feature_state = root / "settings.json"
            setup_state = root / "setup-state.json"
            setup_journal = root / "setup-journal.json"
            first_start = root / "first-start.json"
            self.write_json(catalog, {"schemaVersion": 2, "features": {"core": {"allowedModes": ["off", "always"]}}})
            self.write_json(feature_state, {"schemaVersion": 2, "features": {"core": "always"}, "updatedAt": 1})
            digest = "a" * 64
            self.write_json(setup_state, {"schemaVersion": 1, "status": "complete", "planDigest": digest})
            self.write_json(setup_journal, {"schemaVersion": 1, "status": "complete"})
            self.write_json(first_start, {"schemaVersion": 1, "status": "complete", "planDigest": digest})
            migration_plans = [
                PlannedMigration(MigrationItem("feature-control", str(feature_state), "current", 2, 2, "current")),
                PlannedMigration(MigrationItem("first-run", str(setup_state), "current", 1, 1, "current")),
            ]
            patches = (
                mock.patch.object(nas_doctor, "VERSION_FILE", version),
                mock.patch.object(nas_doctor, "FEATURE_CATALOG", catalog),
                mock.patch.object(nas_doctor, "FEATURE_STATE", feature_state),
                mock.patch.object(nas_doctor, "SETUP_STATE", setup_state),
                mock.patch.object(nas_doctor, "SETUP_JOURNAL", setup_journal),
                mock.patch.object(nas_doctor, "FIRST_START_STATUS", first_start),
                mock.patch.object(nas_doctor, "authorities", return_value=(Authority("test", str(state_authority)),)),
                mock.patch.object(nas_doctor, "plan_all", return_value=migration_plans),
                mock.patch.object(nas_doctor, "operation_state", return_value={"busyClasses": [], "active": []}),
            )
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                report = nas_doctor.build_report()
            self.assertEqual("healthy", report["status"])
            self.assertEqual(0, report["summary"]["critical"])
            self.assertTrue(any(item["id"] == "state.registry" for item in report["checks"]))

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

    def test_doctor_reports_quarantined_alert_router_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "state.json"
            quarantine = root / "state.json.corrupt-1-deadbeef"
            quarantine.write_text("{}\n", encoding="utf-8")
            with mock.patch.object(nas_doctor, "ALERT_ROUTER_STATE", state):
                checks = nas_doctor._alert_router_state_checks()
            self.assertEqual(1, len(checks))
            self.assertEqual("warning", checks[0].status)
            self.assertIn(str(quarantine), checks[0].detail or "")

    def test_manual_recovery_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            version = root / "VERSION"
            version.write_text("2.1.0-alpha.22\n", encoding="utf-8")
            journal = root / "journal.json"
            self.write_json(
                journal,
                {"schemaVersion": 1, "status": "manual-recovery-required", "error": "pool mutation interrupted"},
            )
            catalog = root / "features.json"
            feature_state = root / "settings.json"
            self.write_json(catalog, {"schemaVersion": 2, "features": {"core": {"allowedModes": ["off", "always"]}}})
            self.write_json(feature_state, {"schemaVersion": 2, "features": {"core": "off"}, "updatedAt": 1})
            with (
                mock.patch.object(nas_doctor, "VERSION_FILE", version),
                mock.patch.object(nas_doctor, "SETUP_STATE", root / "missing-state.json"),
                mock.patch.object(nas_doctor, "SETUP_JOURNAL", journal),
                mock.patch.object(nas_doctor, "FIRST_START_STATUS", root / "missing-first.json"),
                mock.patch.object(nas_doctor, "FEATURE_CATALOG", catalog),
                mock.patch.object(nas_doctor, "FEATURE_STATE", feature_state),
                mock.patch.object(nas_doctor, "authorities", return_value=()),
                mock.patch.object(nas_doctor, "plan_all", return_value=[]),
                mock.patch.object(nas_doctor, "operation_state", return_value={"busyClasses": [], "active": []}),
            ):
                report = nas_doctor.build_report()
            self.assertEqual("critical", report["status"])
            self.assertTrue(
                any(item["id"] == "setup.journal" and item["status"] == "critical" for item in report["checks"])
            )


class PackagingContractTests(unittest.TestCase):
    def test_new_commands_and_host_policy_are_packaged(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[1]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        account_tools = (root / "modules/nas/internal/account-tools.nix").read_text(encoding="utf-8")
        options = (root / "modules/nas/options/core.nix").read_text(encoding="utf-8")
        identities = (root / "modules/nas/config/identities.nix").read_text(encoding="utf-8")
        system = (root / "modules/nas/config/system.nix").read_text(encoding="utf-8")
        for command in ("nas-doctor", "nas-migrate-state"):
            self.assertIn(command, pyproject)
            self.assertIn(command, account_tools)
        self.assertIn("mutableLocalPasswords", options)
        self.assertIn("directCockpitRecovery", options)
        self.assertIn("cfg.hostPolicy.mutableLocalPasswords", identities)
        self.assertIn("127.0.0.1:${toString cockpitPort}", system)


if __name__ == "__main__":
    unittest.main()
