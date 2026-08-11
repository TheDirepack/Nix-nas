from __future__ import annotations

import io
import json
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
import nas_setup_config as setup_config  # noqa: E402


class SetupConfigTests(unittest.TestCase):
    def base(self) -> dict:
        return {
            "schemaVersion": 2,
            "storage": {"createPool": False},
            "accounts": [
                {
                    "username": "alice",
                    "name": "Alice",
                    "email": "alice@example.test",
                    "groups": ["nas_users"],
                }
            ],
            "services": {"ai-workspace": "on-demand"},
            "runPreflight": True,
        }

    def test_config_is_v2_native_and_rejects_features(self) -> None:
        value = setup_config.normalize_config(self.base())
        self.assertEqual(value["schemaVersion"], 2)
        self.assertEqual(value["services"], {"ai-workspace": "on-demand"})
        self.assertNotIn("features", value)
        bad = self.base()
        bad["features"] = {"ai": "always"}
        with self.assertRaisesRegex(setup_config.SetupError, "unknown field"):
            setup_config.normalize_config(bad)

    def test_account_config_accepts_only_base_identity_roles(self) -> None:
        value = setup_config.normalize_config(self.base())
        self.assertEqual(value["accounts"][0]["groups"], ["nas_users"])
        for group in ("nas_allow_files", "nas_deny_ai", "application.copyparty.files"):
            bad = self.base()
            bad["accounts"][0]["groups"] = [group]
            with self.subTest(group=group), self.assertRaisesRegex(setup_config.SetupError, "non-role group"):
                setup_config.normalize_config(bad)

    def test_disabled_account_collapses_to_disabled_role(self) -> None:
        raw = self.base()["accounts"][0]
        raw["active"] = False
        raw["groups"] = ["nas_users"]
        value = setup_config.normalize_account(raw, 0)
        self.assertEqual(value["groups"], ["nas_disabled"])

    def test_service_modes_are_closed(self) -> None:
        bad = self.base()
        bad["services"] = {"ai-workspace": "sometimes"}
        with self.assertRaisesRegex(setup_config.SetupError, "off, on-demand, always"):
            setup_config.normalize_config(bad)

    def test_plaintext_account_password_is_rejected(self) -> None:
        bad = self.base()
        bad["accounts"][0]["password"] = "secret"
        with self.assertRaisesRegex(setup_config.SetupError, "plaintext password"):
            setup_config.normalize_config(bad)

    def test_storage_aliases_and_topology_validation_remain_fail_closed(self) -> None:
        bad = self.base()
        bad["storage"] = {"createPool": True, "devices": ["/dev/a", "/dev/a"], "topology": "mirror"}
        with self.assertRaisesRegex(setup_config.SetupError, "Duplicate storage devices"):
            setup_config.normalize_config(bad)
        bad = self.base()
        bad["storage"] = {"createPool": True, "devices": ["/dev/a"], "topology": "raidz1"}
        with self.assertRaisesRegex(setup_config.SetupError, "requires at least 3"):
            setup_config.normalize_config(bad)


class ManagedServicesSetupTests(unittest.TestCase):
    def service_status(self) -> dict:
        return {
            "ok": True,
            "schemaVersion": 3,
            "services": [
                {
                    "id": "ai-workspace",
                    "available": True,
                    "allowedModes": ["off", "on-demand", "always"],
                    "requestedMode": "on-demand",
                },
                {
                    "id": "copyparty",
                    "available": True,
                    "allowedModes": ["off", "always"],
                    "requestedMode": "always",
                },
            ],
        }

    def test_validate_service_request_uses_v2_status(self) -> None:
        with mock.patch.object(setup, "_managed_services_status", return_value=self.service_status()) as status:
            setup.validate_service_request({"ai-workspace": "on-demand"})
        status.assert_called_once_with()

    def test_validate_service_request_rejects_unknown_or_disallowed_mode(self) -> None:
        with mock.patch.object(setup, "_managed_services_status", return_value=self.service_status()):
            with self.assertRaisesRegex(setup.SetupError, "Unknown configured"):
                setup.validate_service_request({"removed-v1-feature": "always"})
            with self.assertRaisesRegex(setup.SetupError, "does not permit mode"):
                setup.validate_service_request({"copyparty": "on-demand"})

    def test_apply_services_calls_only_managed_services_v2_control(self) -> None:
        with (
            mock.patch.object(setup, "coordinated_child", side_effect=lambda value: ["env", "TOKEN=x", *value]),
            mock.patch.object(setup, "run_root", return_value=setup.Completed((), "", "")) as run_root,
        ):
            result = setup.apply_services({"ai-workspace": "always"})
        self.assertEqual(result, {"ai-workspace": "always"})
        command = run_root.call_args.args[0]
        self.assertIn("nas-managed-services-control", command)
        self.assertNotIn("nas-feature-control", command)
        self.assertEqual(command[-2:], ["set-many", "-"])

    def test_service_policy_ready_reads_requested_modes(self) -> None:
        with mock.patch.object(setup, "_managed_services_status", return_value=self.service_status()):
            self.assertTrue(setup.service_policy_ready({"ai-workspace": "on-demand"}))
            self.assertFalse(setup.service_policy_ready({"ai-workspace": "always"}))

    def test_canonical_plan_contains_services_not_features(self) -> None:
        config = setup_config.normalize_config(
            {
                "schemaVersion": 2,
                "storage": {"createPool": False},
                "accounts": [],
                "services": {"ai-workspace": "on-demand"},
                "runPreflight": False,
            }
        )
        plan = setup.canonical_setup_plan(config)
        self.assertEqual(plan["services"], {"ai-workspace": "on-demand"})
        self.assertNotIn("features", plan)
        self.assertRegex(setup.setup_plan_digest(config), r"^[0-9a-f]{64}$")


class ShareProvisioningTests(unittest.TestCase):
    def test_backing_directories_are_not_application_authorization_state(self) -> None:
        accounts = [
            {"username": "alice", "active": True, "groups": ["nas_users"]},
            {"username": "admin2", "active": True, "groups": ["nas_admin"]},
            {"username": "guest", "active": True, "groups": ["nas_guests"]},
            {"username": "disabled", "active": False, "groups": ["nas_disabled"]},
        ]
        calls: list[list[str]] = []

        def capture(command, **_kwargs):
            calls.append(list(command))
            return setup.Completed(tuple(command), "", "")

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(setup, "SHARE_ROOT", pathlib.Path(tmp) / "shares"),
            mock.patch.object(setup, "run_root", side_effect=capture),
        ):
            created = setup.provision_share_directories(accounts)
        self.assertEqual(len(created), 2)
        self.assertTrue(any(path.endswith("/alice") for path in created))
        self.assertTrue(any(path.endswith("/admin2") for path in created))
        self.assertFalse(any(path.endswith("/guest") for path in created))
        rendered = "\n".join(" ".join(call) for call in calls)
        self.assertNotIn("nas_allow_", rendered)
        self.assertNotIn("nas_deny_", rendered)


class FirstStartStatusTests(unittest.TestCase):
    def config_file(self, root: pathlib.Path) -> pathlib.Path:
        path = root / "first-run.json"
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "storage": {"createPool": False},
                    "accounts": [],
                    "services": {"ai-workspace": "on-demand"},
                    "runPreflight": True,
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_prepare_status_reports_service_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = self.config_file(root)
            state = root / "missing-state.json"
            with (
                mock.patch.object(setup, "STATE_PATH", state),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "validate_service_request"),
            ):
                result = setup.first_start_status(str(config))
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["serviceCount"], 1)
        self.assertNotIn("featureCount", result)

    def test_confirmed_plan_digest_must_match_normalized_v2_plan(self) -> None:
        config = setup_config.normalize_config(
            {"schemaVersion": 2, "storage": {"createPool": False}, "accounts": [], "services": {}}
        )
        digest = setup.setup_plan_digest(config)
        self.assertEqual(setup.require_confirmed_plan(config, digest), digest)
        with self.assertRaisesRegex(setup.SetupError, "no longer matches"):
            setup.require_confirmed_plan(config, "0" * 64)

    def test_status_uses_managed_services_key(self) -> None:
        with (
            mock.patch.object(setup.KEEPASS_DATABASE, "exists", return_value=True),
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup, "dataset_exists", return_value=True),
            mock.patch.object(pathlib.Path, "exists", return_value=False),
        ):
            result = setup.status_report()
        self.assertNotIn("features", result)


class CliTests(unittest.TestCase):
    def test_validate_config_cli_outputs_schema_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.json"
            path.write_text(
                json.dumps({"schemaVersion": 2, "storage": {"createPool": False}, "accounts": [], "services": {}}),
                encoding="utf-8",
            )
            with mock.patch.object(sys, "argv", ["nas-setup", "validate-config", str(path)]), mock.patch(
                "sys.stdout", new_callable=io.StringIO
            ) as stdout:
                self.assertEqual(setup.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue())["schemaVersion"], 2)


if __name__ == "__main__":
    unittest.main()
