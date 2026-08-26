from __future__ import annotations

import argparse
import io
import json
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

import nas_setup as setup  # noqa: E402


class SetupRuntimeCoverageTests(unittest.TestCase):
    def test_run_maps_results_timeouts_and_failures(self) -> None:
        result = types.SimpleNamespace(returncode=0, stdout="out", stderr="err")
        with mock.patch.object(setup, "run_command", return_value=result) as command:
            completed = setup.run(["tool", "arg"], input_text="in", env={"A": "B"}, timeout_seconds=7)
        self.assertEqual(completed.command, ("tool", "arg"))
        self.assertEqual(completed.stdout, "out")
        self.assertEqual(command.call_args.kwargs["timeout_seconds"], 7)

        timed_out = types.SimpleNamespace(returncode=124, stdout="", stderr="")
        with mock.patch.object(setup, "run_command", return_value=timed_out):
            with self.assertRaisesRegex(setup.SetupError, "timed out"):
                setup.run(["slow"], timeout_seconds=3)

        failed = types.SimpleNamespace(returncode=2, stdout="fallback", stderr="")
        with mock.patch.object(setup, "run_command", return_value=failed):
            with self.assertRaisesRegex(setup.SetupError, "fallback"):
                setup.run(["bad"])
            self.assertEqual(setup.run(["bad"], check=False).returncode, 2)

    def test_admin_command_handles_admin_root_and_other_users(self) -> None:
        with mock.patch.object(setup, "current_username", return_value=setup.ADMIN_USER):
            self.assertEqual(setup.admin_command(["x"]), ["x"])
        with (
            mock.patch.object(setup, "current_username", return_value="root"),
            mock.patch.object(setup.os, "geteuid", return_value=0),
        ):
            command = setup.admin_command(["x"])
        self.assertEqual(command[:4], ["runuser", "-u", setup.ADMIN_USER, "--"])
        with (
            mock.patch.object(setup, "current_username", return_value="bob"),
            mock.patch.object(setup.os, "geteuid", return_value=1000),
        ):
            with self.assertRaisesRegex(setup.SetupError, "Run nas-setup"):
                setup.admin_command(["x"])

    def test_privileged_runner_branches(self) -> None:
        with mock.patch.object(setup.os, "geteuid", return_value=0), mock.patch.object(setup, "run") as run:
            setup.run_root(["x"])
            run.assert_called_once_with(["x"])
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(
                setup, "run", side_effect=[setup.Completed(("sudo",), "", "", 0), setup.Completed(("x",), "", "")]
            ) as run,
        ):
            setup.run_root(["x"])
        self.assertEqual(run.call_args_list[-1].args[0][:3], ["sudo", "-n", "--"])
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "run", return_value=setup.Completed(("sudo",), "", "expired", 1)),
        ):
            with self.assertRaisesRegex(setup.SetupError, "authorization expired"):
                setup.run_root(["x"])

    def test_noninteractive_root_runner_denies_non_admin_without_sudo(self) -> None:
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "current_username", return_value="bob"),
        ):
            result = setup.run_root_noninteractive(["x"])
        self.assertEqual(result.returncode, 1)
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "current_username", return_value=setup.ADMIN_USER),
            mock.patch.object(setup, "run", return_value=setup.Completed(("x",), "", "")) as run,
        ):
            setup.run_root_noninteractive(["x"])
        self.assertEqual(run.call_args.args[0][:3], ["sudo", "-n", "--"])

    def test_interactive_privileged_uses_root_only_with_explicit_root_mode(self) -> None:
        with (
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.dict(setup.os.environ, {"NAS_SETUP_ALLOW_ROOT": "1"}),
            mock.patch.object(setup, "run") as run,
        ):
            setup.run_interactive_privileged(["x"])
        run.assert_called_once_with(["x"])
        with mock.patch.object(setup.os, "geteuid", return_value=1000), mock.patch.object(setup, "run_admin") as admin:
            setup.run_interactive_privileged(["x"])
        admin.assert_called_once_with(["x"])

    def test_coordination_requires_active_token(self) -> None:
        with mock.patch.object(setup, "current_coordination_token", side_effect=RuntimeError("no token")):
            with self.assertRaisesRegex(setup.SetupError, "without an active"):
                setup.coordinated_child(["x"])
        with mock.patch.object(setup, "current_coordination_token", return_value="abc"):
            self.assertEqual(setup.coordinated_child(["x"]), ["env", f"{setup.COORDINATION_TOKEN_ENV}=abc", "x"])

    def test_require_setup_operator_branches(self) -> None:
        with (
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.dict(setup.os.environ, {"NAS_SETUP_ALLOW_ROOT": "1"}),
            mock.patch.object(setup, "current_username", return_value="root"),
            mock.patch.object(setup, "run") as run,
        ):
            setup.require_setup_operator()
        run.assert_not_called()
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "current_username", return_value="bob"),
        ):
            with self.assertRaisesRegex(setup.SetupError, "Run mutating"):
                setup.require_setup_operator()
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "current_username", return_value=setup.ADMIN_USER),
            mock.patch.object(setup, "run") as run,
        ):
            setup.require_setup_operator()
        run.assert_called_once_with(["sudo", "-v"], capture=False)

    def test_maintained_sudo_authorization_root_path(self) -> None:
        with mock.patch.object(setup, "require_setup_operator"), mock.patch.object(setup.os, "geteuid", return_value=0):
            with setup.maintained_sudo_authorization():
                pass

    def test_read_json_source_file_stdin_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "config.json"
            path.write_text('{"ok":true}', encoding="utf-8")
            self.assertEqual(setup.read_json_source(str(path)), {"ok": True})
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(setup.SetupError, "one object"):
                setup.read_json_source(str(path))
            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(setup.SetupError, "Unable to read"):
                setup.read_json_source(str(path))
        with mock.patch.object(sys, "stdin", io.StringIO('{"stdin":true}')):
            self.assertEqual(setup.read_json_source("-"), {"stdin": True})

    def test_pool_and_dataset_existence_are_command_status(self) -> None:
        for returncode, expected in ((0, True), (1, False)):
            with mock.patch.object(setup.subprocess, "run", return_value=types.SimpleNamespace(returncode=returncode)):
                self.assertEqual(setup.pool_exists(), expected)
                self.assertEqual(setup.dataset_exists(), expected)

    def test_validate_storage_request_preconditions(self) -> None:
        storage = {"createPool": True, "devices": ["/dev/a"]}
        with (
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup.os, "stat") as stat_call,
        ):
            setup.validate_storage_request(storage, [], False)
        stat_call.assert_not_called()
        with mock.patch.object(setup, "pool_exists", return_value=False):
            with self.assertRaisesRegex(setup.SetupError, "does not exist"):
                setup.validate_storage_request({"createPool": False}, [], False)
            with self.assertRaisesRegex(setup.SetupError, "confirm-storage-device"):
                setup.validate_storage_request(storage, [], True)
            with self.assertRaisesRegex(setup.SetupError, "allow-destructive"):
                setup.validate_storage_request(storage, ["/dev/a"], False)

    def test_validate_storage_request_device_checks(self) -> None:
        storage = {"createPool": True, "devices": ["/dev/a"]}
        with (
            mock.patch.object(setup, "pool_exists", return_value=False),
            mock.patch.object(setup.os, "stat", side_effect=FileNotFoundError),
        ):
            with self.assertRaisesRegex(setup.SetupError, "do not exist"):
                setup.validate_storage_request(storage, ["/dev/a"], True)
        regular = types.SimpleNamespace(st_mode=stat.S_IFREG, st_rdev=1)
        with (
            mock.patch.object(setup, "pool_exists", return_value=False),
            mock.patch.object(setup.os, "stat", return_value=regular),
        ):
            with self.assertRaisesRegex(setup.SetupError, "not block devices"):
                setup.validate_storage_request(storage, ["/dev/a"], True)
        block = types.SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=7)
        alias_storage = {"createPool": True, "devices": ["/dev/a", "/dev/b"]}
        with (
            mock.patch.object(setup, "pool_exists", return_value=False),
            mock.patch.object(setup.os, "stat", return_value=block),
        ):
            with self.assertRaisesRegex(setup.SetupError, "same block device"):
                setup.validate_storage_request(alias_storage, ["/dev/a", "/dev/b"], True)
        with (
            mock.patch.object(setup, "pool_exists", return_value=False),
            mock.patch.object(setup.os, "stat", side_effect=OSError("boom")),
        ):
            with self.assertRaisesRegex(setup.SetupError, "Unable to inspect"):
                setup.validate_storage_request(storage, ["/dev/a"], True)

    def test_managed_services_status_validation(self) -> None:
        with mock.patch.object(setup, "run_root", return_value=setup.Completed((), "", "failed", 1)):
            with self.assertRaisesRegex(setup.SetupError, "status failed"):
                setup._managed_services_status()
        with mock.patch.object(setup, "run_root", return_value=setup.Completed((), "{", "", 0)):
            with self.assertRaisesRegex(setup.SetupError, "invalid JSON"):
                setup._managed_services_status()
        for payload in ({}, {"services": {}}):
            with mock.patch.object(setup, "run_root", return_value=setup.Completed((), json.dumps(payload), "", 0)):
                with self.assertRaisesRegex(setup.SetupError, "no service catalog"):
                    setup._managed_services_status()
        good = {"services": [{"id": "demo"}]}
        with mock.patch.object(
            setup, "run_root_noninteractive", return_value=setup.Completed((), json.dumps(good), "", 0)
        ) as runner:
            self.assertEqual(setup._managed_services_status(noninteractive=True), good)
        runner.assert_called_once()

    def test_validate_service_request_empty_unavailable_and_bad_modes(self) -> None:
        with mock.patch.object(setup, "_managed_services_status") as status:
            setup.validate_service_request({})
        status.assert_not_called()
        catalog = {
            "services": [
                {"id": "demo", "allowedModes": ["off", "always"], "available": False},
                {"id": 1, "allowedModes": ["off"], "available": True},
                "bad",
            ]
        }
        with mock.patch.object(setup, "_managed_services_status", return_value=catalog):
            with self.assertRaisesRegex(setup.SetupError, "Unknown configured"):
                setup.validate_service_request({"missing": "off"})
            with self.assertRaisesRegex(setup.SetupError, "does not permit"):
                setup.validate_service_request({"demo": "on-demand"})
            with self.assertRaisesRegex(setup.SetupError, "unavailable"):
                setup.validate_service_request({"demo": "always"})
            setup.validate_service_request({"demo": "off"})

    def test_identity_plan_reads_only_declared_password_files(self) -> None:
        config = {
            "accounts": [
                {
                    "username": "alice",
                    "name": "Alice",
                    "email": "a@x",
                    "active": True,
                    "groups": [setup.USER_GROUP],
                    "attributes": {},
                    "passwordFile": "/secret",
                },
                {
                    "username": "bob",
                    "name": "Bob",
                    "email": "b@x",
                    "active": True,
                    "groups": [setup.USER_GROUP],
                    "attributes": {},
                    "passwordFile": None,
                },
            ],
            "deactivateMissingManagedAccounts": True,
        }
        with mock.patch.object(setup, "read_password_file", return_value="password") as reader:
            plan = setup.identity_plan(config)
        self.assertEqual(plan["accounts"][0]["password"], "password")
        self.assertNotIn("password", plan["accounts"][1])
        reader.assert_called_once_with("/secret", "alice")

    def test_read_keepass_password_uses_stdin_or_prompt(self) -> None:
        with mock.patch.object(setup, "read_secret_stdin", return_value="stdin") as read:
            self.assertEqual(setup.read_keepass_password(True), "stdin")
        read.assert_called_once()
        with (
            mock.patch.object(setup.getpass, "getpass", return_value="prompt\n"),
            mock.patch.object(setup, "normalize_secret_line", return_value="prompt") as normalize,
        ):
            self.assertEqual(setup.read_keepass_password(False), "prompt")
        normalize.assert_called_once()

    def test_verify_or_create_keepass_database_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            database = root / "NAS.kdbx"
            database.write_text("x", encoding="utf-8")
            with mock.patch.object(setup, "KEEPASS_DATABASE", database), mock.patch.object(setup, "run_admin") as admin:
                self.assertEqual(setup.verify_or_create_database("pw", False), "existing")
            self.assertIn("db-info", admin.call_args.args[0])
            database.unlink()
            with mock.patch.object(setup, "KEEPASS_DATABASE", database):
                with self.assertRaisesRegex(setup.SetupError, "does not exist"):
                    setup.verify_or_create_database("pw", False)

            def create(_command: object, **_kwargs: object) -> setup.Completed:
                database.write_text("created", encoding="utf-8")
                return setup.Completed((), "", "")

            with (
                mock.patch.object(setup, "KEEPASS_DATABASE", database),
                mock.patch.object(setup, "run_root"),
                mock.patch.object(setup, "run_admin", side_effect=create),
            ):
                self.assertEqual(setup.verify_or_create_database("pw", True), "created")

    def test_verify_or_create_database_reports_failed_creation_and_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            database = pathlib.Path(raw) / "NAS.kdbx"
            with (
                mock.patch.object(setup, "KEEPASS_DATABASE", database),
                mock.patch.object(setup, "KEEPASS_KEY_FILE", "/key"),
                mock.patch.object(setup, "run_root"),
                mock.patch.object(setup, "run_admin") as admin,
            ):
                with self.assertRaisesRegex(setup.SetupError, "did not create"):
                    setup.verify_or_create_database("pw", True)
            self.assertIn("--set-key-file", admin.call_args.args[0])

    def test_setup_storage_creates_plain_pool_and_dataset(self) -> None:
        calls: list[list[str]] = []
        storage = {
            "createPool": True,
            "devices": ["/dev/a", "/dev/b"],
            "topology": "mirror",
            "ashift": 13,
            "wipeDevices": True,
        }
        with (
            mock.patch.object(setup, "pool_exists", return_value=False),
            mock.patch.object(setup, "dataset_exists", return_value=False),
            mock.patch.object(setup, "validate_storage_request"),
            mock.patch.object(setup, "ZFS_ENCRYPTION", False),
            mock.patch.object(
                setup,
                "run_root",
                side_effect=lambda command, **_kwargs: (
                    calls.append(list(command)) or setup.Completed(tuple(command), "", "")
                ),
            ),
        ):
            result = setup.setup_storage(
                storage, keepass_password="pw", confirmed_devices=["/dev/a", "/dev/b"], allow_destructive=True
            )
        self.assertTrue(result["createdPool"])
        self.assertTrue(result["createdDataset"])
        rendered = [" ".join(call) for call in calls]
        self.assertTrue(any("wipefs --all --force /dev/a" in line for line in rendered))
        self.assertTrue(any("zpool create" in line and "mirror /dev/a /dev/b" in line for line in rendered))
        self.assertTrue(any("zfs create" in line for line in rendered))

    def test_setup_storage_encrypted_dataset_uses_privileged_helper(self) -> None:
        with (
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup, "dataset_exists", return_value=False),
            mock.patch.object(setup, "ZFS_ENCRYPTION", True),
            mock.patch.object(setup, "run_interactive_privileged") as privileged,
            mock.patch.object(setup, "run_root") as root,
        ):
            result = setup.setup_storage(
                {"createPool": False}, keepass_password="pw", confirmed_devices=[], allow_destructive=False
            )
        privileged.assert_called_once_with(["nas-zfs-create-encrypted-dataset"], input_text="pw\n")
        root.assert_not_called()
        self.assertTrue(result["encrypted"])

    def test_apply_accounts_validates_json_result_and_confirmation_flag(self) -> None:
        with (
            mock.patch.object(setup, "coordinated_child", side_effect=lambda command: list(command)),
            mock.patch.object(setup, "run_root", return_value=setup.Completed((), '{"created":[]}', "")) as root,
        ):
            self.assertEqual(setup.apply_accounts({"accounts": []}, confirm_password_reapply=True), {"created": []})
        self.assertIn("--confirm-password-reapply", root.call_args.args[0])
        with (
            mock.patch.object(setup, "coordinated_child", side_effect=lambda command: list(command)),
            mock.patch.object(setup, "run_root", return_value=setup.Completed((), "{", "")),
        ):
            with self.assertRaisesRegex(setup.SetupError, "invalid account JSON"):
                setup.apply_accounts({"accounts": []})
        with (
            mock.patch.object(setup, "coordinated_child", side_effect=lambda command: list(command)),
            mock.patch.object(setup, "run_root", return_value=setup.Completed((), "[]", "")),
        ):
            with self.assertRaisesRegex(setup.SetupError, "invalid account result"):
                setup.apply_accounts({"accounts": []})

    def test_provision_share_directories_skips_guests_and_inactive(self) -> None:
        calls: list[list[str]] = []
        accounts = [
            {"username": "alice", "active": True, "groups": [setup.USER_GROUP]},
            {"username": "guest", "active": True, "groups": [setup.GUEST_GROUP]},
            {"username": "off", "active": False, "groups": [setup.USER_GROUP]},
        ]
        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch.object(setup, "SHARE_ROOT", pathlib.Path(raw)),
            mock.patch.object(
                setup,
                "run_root",
                side_effect=lambda command, **_kwargs: (
                    calls.append(list(command)) or setup.Completed(tuple(command), "", "")
                ),
            ),
        ):
            created = setup.provision_share_directories(accounts)
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].endswith("/alice"))
        self.assertFalse(any(call[-1].endswith("/guest") for call in calls))

    def test_apply_services_is_noop_for_empty_and_calls_v2_for_values(self) -> None:
        with mock.patch.object(setup, "run_root") as root:
            self.assertEqual(setup.apply_services({}), {})
        root.assert_not_called()
        with (
            mock.patch.object(setup, "coordinated_child", side_effect=lambda command: ["env", *command]),
            mock.patch.object(setup, "run_root") as root,
        ):
            result = setup.apply_services({"demo": "always"})
        self.assertEqual(result, {"demo": "always"})
        self.assertIn(setup.MANAGED_SERVICES_CONTROL, root.call_args.args[0])

    def test_password_input_authenticators_are_not_persisted(self) -> None:
        self.assertFalse(hasattr(setup, "password_input_authenticators"))
        source = pathlib.Path(setup.__file__).read_text(encoding="utf-8")
        self.assertNotIn("def password_input_authenticators", source)

    def test_canonical_plan_digest_and_confirmation(self) -> None:
        config = {
            "storage": {"createPool": False},
            "accounts": [
                {
                    "username": "alice",
                    "name": "A",
                    "email": "a@x",
                    "active": True,
                    "groups": [setup.USER_GROUP],
                    "attributes": {},
                    "passwordFile": "/x",
                },
                1,
            ],
            "services": {"demo": "off"},
            "deactivateMissingManagedAccounts": False,
            "runPreflight": True,
        }
        plan = setup.canonical_setup_plan(config)
        self.assertTrue(plan["accounts"][0]["passwordInput"])
        self.assertEqual(len(plan["accounts"]), 1)
        digest = setup.setup_plan_digest(config)
        self.assertEqual(setup.require_confirmed_plan(config, digest), digest)
        for supplied in (None, "0" * 64):
            with self.assertRaisesRegex(setup.SetupError, "no longer matches"):
                setup.require_confirmed_plan(config, supplied)

    def test_setup_fingerprint_changes_with_execution_controls(self) -> None:
        config = {"storage": {}, "accounts": [], "services": {}, "runPreflight": False}
        args = argparse.Namespace(
            create_database=False, confirm_storage_device=[], allow_destructive_storage=False, skip_preflight=False
        )
        administrator = {"username": "nasadmin", "name": "NAS Administrator", "email": "admin@example.test"}
        first = setup.setup_fingerprint(config, args, administrator)
        args.skip_preflight = True
        second = setup.setup_fingerprint(config, args, administrator)
        self.assertNotEqual(first, second)

    def test_install_runtime_identity_token_validates_and_installs(self) -> None:
        response = {"token": "runtime-token", "username": "service"}
        with (
            mock.patch.object(setup, "coordinated_child", side_effect=lambda command: list(command)),
            mock.patch.object(setup, "run_root", return_value=setup.Completed((), json.dumps(response), "")),
            mock.patch.object(setup, "run_admin") as admin,
            mock.patch.object(setup, "run_interactive_privileged") as privileged,
        ):
            result = setup.install_runtime_identity_token("keepass")
        self.assertEqual(result, {"username": "service"})
        self.assertIn("runtime-token", admin.call_args.kwargs["input_text"])
        privileged.assert_called_once()
        for stdout in ("{", "{}", "[]"):
            with (
                mock.patch.object(setup, "coordinated_child", side_effect=lambda command: list(command)),
                mock.patch.object(setup, "run_root", return_value=setup.Completed((), stdout, "")),
            ):
                with self.assertRaises(setup.SetupError):
                    setup.install_runtime_identity_token("keepass")

    def test_readiness_helpers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            missing = pathlib.Path(raw) / "missing"
            with mock.patch.object(setup, "KEEPASS_DATABASE", missing):
                self.assertFalse(setup.keepass_database_ready())
            regular = pathlib.Path(raw) / "db"
            regular.write_text("x", encoding="utf-8")
            with mock.patch.object(setup, "KEEPASS_DATABASE", regular):
                self.assertTrue(setup.keepass_database_ready())
        with (
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup, "dataset_exists", return_value=False),
        ):
            self.assertFalse(setup.storage_ready())
        with mock.patch.object(setup, "run_root_noninteractive", return_value=setup.Completed((), "{", "", 0)):
            self.assertFalse(setup.identity_command_ready(["x"]))
        with mock.patch.object(
            setup, "run_root_noninteractive", return_value=setup.Completed((), '{"error":"bad"}', "", 0)
        ):
            self.assertFalse(setup.identity_command_ready(["x"]))
        with mock.patch.object(
            setup, "run_root_noninteractive", return_value=setup.Completed((), '{"ok":true}', "", 0)
        ):
            self.assertTrue(setup.identity_command_ready(["x"]))

    def test_account_plan_ready_compares_exported_fields(self) -> None:
        desired = {
            "username": "alice",
            "name": "Alice",
            "email": "a@x",
            "active": True,
            "groups": [setup.USER_GROUP],
            "attributes": {"x": 1},
        }
        with mock.patch.object(
            setup, "run_root_noninteractive", return_value=setup.Completed((), json.dumps(desired), "", 0)
        ):
            self.assertTrue(setup.account_plan_ready({"accounts": [desired]}))
        bad = dict(desired)
        bad["email"] = "wrong"
        with mock.patch.object(
            setup, "run_root_noninteractive", return_value=setup.Completed((), json.dumps(bad), "", 0)
        ):
            self.assertFalse(setup.account_plan_ready({"accounts": [desired]}))
        self.assertFalse(setup.account_plan_ready({"accounts": [1]}))

    def test_service_policy_ready_and_state_match_fail_closed(self) -> None:
        with mock.patch.object(setup, "_managed_services_status", side_effect=setup.SetupError("no")):
            self.assertFalse(setup.service_policy_ready({"demo": "always"}))
        with mock.patch.object(
            setup, "_managed_services_status", return_value={"services": [{"id": "demo", "requestedMode": "always"}]}
        ):
            self.assertTrue(setup.service_policy_ready({"demo": "always"}))
            self.assertFalse(setup.service_policy_ready({"demo": "off"}))
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "state.json"
            with mock.patch.object(setup, "STATE_PATH", path):
                self.assertFalse(setup.setup_state_matches({"x": 1}))
                path.write_text('{"x":1}', encoding="utf-8")
                self.assertTrue(setup.setup_state_matches({"x": 1}))


if __name__ == "__main__":
    unittest.main()