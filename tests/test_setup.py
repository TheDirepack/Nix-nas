from __future__ import annotations

import importlib.util
import json
import io
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES))
SPEC = importlib.util.spec_from_file_location("nas_setup", SERVICES / "nas_setup.py")
assert SPEC and SPEC.loader
setup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = setup
SPEC.loader.exec_module(setup)


class SetupConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        # Exercise the real coordinator in an isolated operation root rather than
        # relying on /run/nas-operations being provisioned on the test host.
        self._operation_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._operation_tmp.cleanup)
        self._operation_patch = mock.patch.dict(
            setup.current_coordination_token.__globals__,
            {"OPERATION_ROOT": pathlib.Path(self._operation_tmp.name)},
        )
        self._operation_patch.start()
        self.addCleanup(self._operation_patch.stop)

    def base(self):
        return {
            "schemaVersion": 1,
            "storage": {"createPool": False},
            "accounts": [
                {
                    "username": "alice",
                    "name": "Alice",
                    "email": "alice@nas.local",
                    "groups": ["nas_allow_files", "nas_allow_vault"],
                }
            ],
            "features": {"aiRuntime": "on-demand"},
        }

    def test_normalization_adds_baseline_user_group(self):
        normalized = setup.normalize_config(self.base())
        account = normalized["accounts"][0]
        self.assertEqual(account["username"], "alice")
        self.assertIn("nas_users", account["groups"])
        self.assertIn("nas_allow_files", account["groups"])
        self.assertEqual(normalized["features"], {"aiRuntime": "on-demand"})

    def test_syncthing_attributes_are_validated_and_canonicalized(self):
        raw = self.base()
        raw["accounts"][0]["attributes"] = {"nasSyncthingDevices": []}
        normalized = setup.normalize_config(raw)
        self.assertEqual(normalized["accounts"][0]["attributes"]["nasSyncthingDevices"], [])

        raw["accounts"][0]["attributes"] = {"nasSyncthingDevices": [None]}
        with self.assertRaisesRegex(setup.SetupError, "invalid Syncthing devices"):
            setup.normalize_config(raw)

        raw["accounts"][0]["attributes"] = {
            "nasSyncthingDevices": [],
            "nasSyncthingDevice": [],
        }
        with self.assertRaisesRegex(setup.SetupError, "must not define both"):
            setup.normalize_config(raw)

    def test_plaintext_passwords_are_rejected(self):
        raw = self.base()
        raw["accounts"][0]["password"] = "not-allowed"
        with self.assertRaisesRegex(setup.SetupError, "plaintext password"):
            setup.normalize_config(raw)

    def test_unknown_schema_fields_and_relative_password_paths_are_rejected(self):
        raw = self.base()
        raw["runPrefligth"] = True
        with self.assertRaisesRegex(setup.SetupError, "unknown field"):
            setup.normalize_config(raw)

        raw = self.base()
        raw["storage"]["toplogy"] = "mirror"
        with self.assertRaisesRegex(setup.SetupError, "storage contains unknown field"):
            setup.normalize_config(raw)

        raw = self.base()
        raw["accounts"][0]["emali"] = "alice@nas.local"
        with self.assertRaisesRegex(setup.SetupError, r"accounts\[0\] contains unknown field"):
            setup.normalize_config(raw)

        raw = self.base()
        raw["accounts"][0]["passwordFile"] = "relative.password"
        with self.assertRaisesRegex(setup.SetupError, "absolute path"):
            setup.normalize_config(raw)

    def test_unknown_groups_and_duplicate_accounts_are_rejected(self):
        raw = self.base()
        raw["accounts"][0]["groups"] = ["unknown_group"]
        with self.assertRaisesRegex(setup.SetupError, "unknown reserved groups"):
            setup.normalize_config(raw)

        raw = self.base()
        raw["accounts"].append(dict(raw["accounts"][0]))
        with self.assertRaisesRegex(setup.SetupError, "Duplicate setup accounts"):
            setup.normalize_config(raw)

    def test_disabled_administrator_is_rejected(self):
        raw = self.base()
        raw["accounts"][0]["groups"] = ["nas_admin"]
        raw["accounts"][0]["active"] = False
        with self.assertRaisesRegex(setup.SetupError, "cannot disable"):
            setup.normalize_config(raw)

    def test_password_file_must_be_private_and_is_only_in_transient_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            password_file = pathlib.Path(tmp) / "alice.password"
            password_file.write_text("correct horse battery staple\n")
            os.chmod(password_file, 0o600)
            raw = self.base()
            raw["accounts"][0]["passwordFile"] = str(password_file)
            normalized = setup.normalize_config(raw)
            self.assertNotIn("password", normalized["accounts"][0])
            plan = setup.identity_plan(normalized)
            self.assertEqual(plan["accounts"][0]["password"], "correct horse battery staple")

            symlink = pathlib.Path(tmp) / "linked.password"
            symlink.symlink_to(password_file)
            raw["accounts"][0]["passwordFile"] = str(symlink)
            linked = setup.normalize_config(raw)
            with self.assertRaisesRegex(setup.SetupError, "without following symlinks"):
                setup.identity_plan(linked)

            os.chmod(password_file, 0o644)
            with self.assertRaisesRegex(setup.SetupError, "group/other"):
                setup.identity_plan(normalized)

    def test_first_run_opens_each_account_password_file_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            password_file = pathlib.Path(tmp) / "alice.password"
            password_file.write_text("account-password\n")
            os.chmod(password_file, 0o600)
            config_path = pathlib.Path(tmp) / "first-run.json"
            config_path.write_text(
                json.dumps(
                    {
                        "storage": {"createPool": False},
                        "accounts": [
                            {
                                "username": "alice",
                                "groups": ["nas_allow_files"],
                                "passwordFile": str(password_file),
                            }
                        ],
                        "features": {},
                        "runPreflight": False,
                    }
                )
            )
            args = mock.Mock(
                config=str(config_path),
                keepass_password_stdin=True,
                create_database=True,
                confirm_storage_device=[],
                allow_destructive_storage=False,
                skip_preflight=False,
            )
            args.confirm_plan_digest = setup.setup_plan_digest(
                setup.normalize_config(json.loads(config_path.read_text()))
            )
            original = setup.read_password_file
            reads = []

            def counted(path, label):
                reads.append((path, label))
                return original(path, label)

            journal_path = pathlib.Path(tmp) / "first-run-journal.json"
            with (
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
                mock.patch.object(setup, "FIRST_START_STATUS_PATH", pathlib.Path(tmp) / "first-start-status.json"),
                mock.patch.object(setup, "require_setup_operator"),
                mock.patch.object(setup, "validate_storage_request"),
                mock.patch.object(setup, "validate_feature_request"),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "read_password_file", side_effect=counted),
                mock.patch.object(setup, "read_keepass_password", return_value="keepass-password"),
                mock.patch.object(setup, "verify_or_create_database", return_value="existing"),
                mock.patch.object(setup, "run_admin"),
                mock.patch.object(
                    setup,
                    "setup_storage",
                    return_value={"createdPool": False, "createdDataset": False, "encrypted": False},
                ),
                mock.patch.object(
                    setup, "apply_accounts", return_value={"created": [], "updated": ["alice"]}
                ) as apply_mock,
                mock.patch.object(setup, "provision_share_directories", return_value=[]),
                mock.patch.object(setup, "apply_features", return_value={}),
                mock.patch.object(
                    setup,
                    "run_root",
                    side_effect=lambda command, **kwargs: setup.Completed(
                        tuple(command),
                        json.dumps({"administrators": ["akadmin"]})
                        if command == ["nas-identity-sync", "status"]
                        else json.dumps(
                            {"token": "runtime-token-value-abcdefghijklmnopqrstuvwxyz", "username": "nas-automation"}
                        )
                        if command == setup.coordinated_child(["nas-identity-sync", "bootstrap-runtime-token"])
                        else "{}",
                        "",
                    ),
                ),
                mock.patch.object(setup, "write_state"),
                mock.patch.object(setup, "setup_state_matches", return_value=True),
            ):
                setup.first_run(args)

            self.assertEqual(reads, [(str(password_file), "alice")])
            transient_plan = apply_mock.call_args.args[0]
            self.assertNotIn("password", transient_plan["accounts"][0])

    def test_secret_stdin_requires_exactly_one_line(self):
        with mock.patch.object(setup.sys, "stdin", io.StringIO("one-password\n")):
            self.assertEqual(setup.read_secret_stdin("test secret"), "one-password")
        for value in ["", "first\nsecond\n", "bad\rline"]:
            with self.subTest(value=value), mock.patch.object(setup.sys, "stdin", io.StringIO(value)):
                with self.assertRaises(setup.SetupError):
                    setup.read_secret_stdin("test secret")

    def test_storage_creation_requires_device_and_explicit_confirmation(self):
        raw = self.base()
        raw["storage"] = {"createPool": True}
        with self.assertRaisesRegex(setup.SetupError, "requires at least 1 device"):
            setup.normalize_config(raw)

        storage = {"createPool": True, "device": "/dev/vdz", "wipeDevice": False}
        with mock.patch.object(setup, "pool_exists", return_value=False):
            with self.assertRaisesRegex(setup.SetupError, "confirm-storage-device"):
                setup.setup_storage(
                    setup.normalize_config({"storage": storage})["storage"],
                    keepass_password="password",
                    confirmed_devices=None,
                    allow_destructive=False,
                )

    def test_feature_request_is_checked_before_mutation(self):
        payload = {
            "features": [
                {"id": "aiRuntime", "available": True, "allowedModes": ["off", "on-demand", "always"]},
                {"id": "gpuOnly", "available": False, "allowedModes": ["off", "on-demand"]},
            ]
        }
        completed = setup.Completed(("nas-feature-control", "status"), json.dumps(payload), "")
        with mock.patch.object(setup, "run_root", return_value=completed):
            setup.validate_feature_request({"aiRuntime": "on-demand"})
            with self.assertRaisesRegex(setup.SetupError, "Unknown configured feature"):
                setup.validate_feature_request({"missing": "off"})
            with self.assertRaisesRegex(setup.SetupError, "not available"):
                setup.validate_feature_request({"gpuOnly": "on-demand"})

    def test_first_run_rejects_missing_pool_before_reading_keepass(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "first-run.json"
            config.write_text(json.dumps({"storage": {"createPool": False}, "runPreflight": False}))
            args = mock.Mock(
                config=str(config),
                confirm_storage_device=[],
                allow_destructive_storage=False,
                keepass_password_stdin=True,
            )
            args.confirm_plan_digest = setup.setup_plan_digest(setup.normalize_config(json.loads(config.read_text())))
            with (
                mock.patch.object(setup, "current_username", return_value=setup.ADMIN_USER),
                mock.patch.object(setup, "run", return_value=setup.Completed(("sudo", "-v"), "", "")),
                mock.patch.object(setup, "pool_exists", return_value=False),
                mock.patch.object(setup, "read_keepass_password") as password_mock,
            ):
                with self.assertRaisesRegex(setup.SetupError, "does not exist"):
                    setup.first_run(args)
            password_mock.assert_not_called()

    def test_first_run_orchestrates_existing_authorities_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = pathlib.Path(tmp) / "first-run.json"
            config_path.write_text(
                json.dumps(
                    {
                        "storage": {"createPool": False},
                        "accounts": [{"username": "alice", "groups": ["nas_allow_files"]}],
                        "features": {},
                        "runPreflight": False,
                    }
                )
            )
            args = mock.Mock(
                config=str(config_path),
                keepass_password_stdin=True,
                create_database=True,
                confirm_storage_device=[],
                allow_destructive_storage=False,
                skip_preflight=False,
            )
            args.confirm_plan_digest = setup.setup_plan_digest(
                setup.normalize_config(json.loads(config_path.read_text()))
            )
            events = []

            def fake_admin(command, **kwargs):
                events.append(("admin", tuple(command)))
                return setup.Completed(tuple(command), "", "")

            def fake_root(command, **kwargs):
                events.append(("root", tuple(command)))
                if command == ["nas-identity-sync", "status"]:
                    return setup.Completed(tuple(command), json.dumps({"administrators": ["akadmin"]}), "")
                if command == setup.coordinated_child(["nas-identity-sync", "bootstrap-runtime-token"]):
                    return setup.Completed(
                        tuple(command),
                        json.dumps(
                            {"token": "runtime-token-value-abcdefghijklmnopqrstuvwxyz", "username": "nas-automation"}
                        ),
                        "",
                    )
                return setup.Completed(tuple(command), "{}", "")

            journal_path = pathlib.Path(tmp) / "first-run-journal.json"
            with (
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
                mock.patch.object(setup, "FIRST_START_STATUS_PATH", pathlib.Path(tmp) / "first-start-status.json"),
                mock.patch.object(setup, "require_setup_operator"),
                mock.patch.object(setup, "validate_storage_request"),
                mock.patch.object(setup, "validate_feature_request"),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "read_keepass_password", return_value="keepass-password"),
                mock.patch.object(setup, "verify_or_create_database", return_value="created"),
                mock.patch.object(setup, "run_admin", side_effect=fake_admin),
                mock.patch.object(
                    setup,
                    "setup_storage",
                    return_value={"createdPool": True, "createdDataset": True, "encrypted": False},
                ),
                mock.patch.object(
                    setup,
                    "apply_accounts",
                    return_value={"created": ["alice"], "updated": [], "passwordsChanged": []},
                ),
                mock.patch.object(setup, "provision_share_directories", return_value=["/tank/shares/users/alice"]),
                mock.patch.object(setup, "apply_features", return_value={}),
                mock.patch.object(setup, "run_root", side_effect=fake_root),
                mock.patch.object(setup, "write_state") as write_state,
                mock.patch.object(setup, "setup_state_matches", return_value=True),
            ):
                result = setup.first_run(args)

            def coordinated_payload(event: tuple[str, tuple[str, ...]]) -> tuple[str, tuple[str, ...]]:
                actor, command = event
                if command and command[0] == "env" and command[1].startswith("NAS_OPERATION_COORDINATION_TOKEN="):
                    return actor, command[2:]
                return event

            normalized_events = [coordinated_payload(event) for event in events]
            self.assertEqual(
                [event for event in normalized_events if event[0] == "admin"],
                [
                    ("admin", ("nas-secrets", "init")),
                    ("admin", ("nas-secrets", "activate-stdin")),
                    ("admin", ("nas-secrets", "set-authentik-token-stdin")),
                    ("admin", ("nas-secrets", "activate-stdin")),
                ],
            )
            self.assertIn(("root", ("nas-identity-sync", "bootstrap")), normalized_events)
            self.assertIn(("root", ("nas-identity-sync", "bootstrap-runtime-token")), normalized_events)
            self.assertIn(("admin", ("nas-secrets", "set-authentik-token-stdin")), normalized_events)
            self.assertIn(("admin", ("nas-secrets", "activate-stdin")), normalized_events)
            self.assertIn(("root", ("nas-zfs-mount-check",)), events)
            self.assertEqual(result["accounts"]["created"], ["alice"])
            write_state.assert_called_once()

    def test_first_start_job_result_retention_is_bounded(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(setup, "FIRST_START_JOB_RETAIN_COUNT", 2),
            mock.patch.object(setup, "FIRST_START_JOB_RETAIN_SECONDS", 0),
        ):
            root = pathlib.Path(temporary)
            paths = []
            for index in range(4):
                path = root / f"{index}.json"
                path.write_text("{}", encoding="utf-8")
                os.utime(path, (100 + index, 100 + index))
                paths.append(path)
            setup.prune_first_start_job_results(root, keep=paths[-1])
            self.assertTrue(paths[-1].exists())
            remaining = sorted(item.name for item in root.glob("*.json"))
            self.assertEqual(remaining, ["2.json", "3.json"])

    def test_first_run_resumes_completed_stages_from_matching_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = pathlib.Path(tmp) / "first-run.json"
            config_path.write_text(
                json.dumps({"storage": {"createPool": False}, "features": {}, "runPreflight": False})
            )
            journal_path = pathlib.Path(tmp) / "first-run-journal.json"
            args = mock.Mock(
                config=str(config_path),
                keepass_password_stdin=True,
                create_database=True,
                confirm_storage_device=[],
                allow_destructive_storage=False,
                skip_preflight=False,
            )
            normalized = setup.normalize_config(json.loads(config_path.read_text()))
            args.confirm_plan_digest = setup.setup_plan_digest(normalized)
            fingerprint = setup.setup_fingerprint(normalized, args, setup.identity_plan(normalized), "keepass-password")
            journal = setup.OperationJournal.open(journal_path, workflow="first-run", fingerprint=fingerprint)
            journal.start_step("keepass-database")
            journal.complete_step("keepass-database", "existing")

            with (
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
                mock.patch.object(setup, "FIRST_START_STATUS_PATH", pathlib.Path(tmp) / "first-start-status.json"),
                mock.patch.object(setup, "require_setup_operator"),
                mock.patch.object(setup, "validate_storage_request"),
                mock.patch.object(setup, "validate_feature_request"),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "read_keepass_password", return_value="keepass-password"),
                mock.patch.object(setup, "verify_or_create_database") as database,
                mock.patch.object(setup, "run_admin", return_value=setup.Completed(("command",), "", "")),
                mock.patch.object(
                    setup,
                    "setup_storage",
                    return_value={"createdPool": False, "createdDataset": False, "encrypted": False},
                ),
                mock.patch.object(setup, "apply_accounts", return_value={}),
                mock.patch.object(setup, "provision_share_directories", return_value=[]),
                mock.patch.object(setup, "apply_features", return_value={}),
                mock.patch.object(
                    setup,
                    "run_root",
                    side_effect=lambda command, **kwargs: setup.Completed(
                        tuple(command),
                        json.dumps(
                            {"token": "runtime-token-value-abcdefghijklmnopqrstuvwxyz", "username": "nas-automation"}
                        )
                        if command == setup.coordinated_child(["nas-identity-sync", "bootstrap-runtime-token"])
                        else json.dumps({"administrators": ["akadmin"]}),
                        "",
                    ),
                ),
                mock.patch.object(setup, "write_state"),
                mock.patch.object(setup, "setup_state_matches", return_value=True),
                mock.patch.object(setup, "keepass_database_ready", return_value=True),
            ):
                result = setup.first_run(args)

            database.assert_not_called()
            self.assertEqual(result["database"]["result"], "existing")
            self.assertEqual(json.loads(journal_path.read_text())["status"], "complete")

    def test_multi_device_topology_and_recommended_pool_properties(self):
        normalized = setup.normalize_config(
            {
                "storage": {
                    "createPool": True,
                    "devices": ["/dev/null", "/dev/zero"],
                    "topology": "mirror",
                    "wipeDevices": True,
                    "ashift": 12,
                }
            }
        )
        commands = []

        def fake_root(command, **kwargs):
            commands.append(command)
            return setup.Completed(tuple(command), "", "")

        with (
            mock.patch.object(setup, "pool_exists", return_value=False),
            mock.patch.object(setup, "dataset_exists", return_value=True),
            mock.patch.object(setup, "validate_storage_request"),
            mock.patch.object(setup, "ZFS_ENCRYPTION", True),
            mock.patch.object(setup, "run_root", side_effect=fake_root),
        ):
            result = setup.setup_storage(
                normalized["storage"],
                keepass_password="password",
                confirmed_devices=["/dev/zero", "/dev/null"],
                allow_destructive=True,
            )
        create = next(command for command in commands if command[:2] == ["zpool", "create"])
        self.assertIn("ashift=12", create)
        self.assertIn("compression=zstd", create)
        self.assertEqual(create[-3:], ["mirror", "/dev/null", "/dev/zero"])
        self.assertIn(["zpool", "set", "autotrim=on", setup.ZFS_POOL], commands)
        self.assertEqual(result["creationRequest"]["topology"], "mirror")

    def test_storage_creation_requires_real_unique_block_devices(self):
        storage = setup.normalize_config(
            {
                "storage": {
                    "createPool": True,
                    "device": "/dev/null",
                    "topology": "single",
                }
            }
        )["storage"]
        with mock.patch.object(setup, "pool_exists", return_value=False):
            with self.assertRaisesRegex(setup.SetupError, "not block devices"):
                setup.validate_storage_request(storage, ["/dev/null"], True)

        with self.assertRaisesRegex(setup.SetupError, "parent-directory traversal"):
            setup.normalize_config({"storage": {"createPool": True, "device": "/dev/../etc/passwd"}})

    def test_invalid_topology_device_counts_are_rejected(self):
        for topology, devices in {
            "single": ["/dev/a", "/dev/b"],
            "mirror": ["/dev/a"],
            "raidz1": ["/dev/a", "/dev/b"],
            "raidz2": ["/dev/a", "/dev/b", "/dev/c"],
            "raidz3": ["/dev/a", "/dev/b", "/dev/c", "/dev/d"],
        }.items():
            with self.subTest(topology=topology), self.assertRaises(setup.SetupError):
                setup.normalize_config({"storage": {"createPool": True, "devices": devices, "topology": topology}})

    def test_privileged_commands_never_prompt_or_consume_payload_stdin(self):
        refresh = setup.Completed(("sudo", "-n", "-v"), "", "")
        executed = setup.Completed(("sudo", "-n", "--", "example"), "ok", "")
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "run", side_effect=[refresh, executed]) as run_mock,
        ):
            result = setup.run_root(["example"], input_text="transient-json\n")
        self.assertEqual(result.stdout, "ok")
        self.assertEqual(
            run_mock.call_args_list,
            [
                mock.call(["sudo", "-n", "-v"], check=False),
                mock.call(
                    ["sudo", "-n", "--", "example"],
                    input_text="transient-json\n",
                ),
            ],
        )

        expired = setup.Completed(("sudo", "-n", "-v"), "", "expired", 1)
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "run", return_value=expired) as run_mock,
        ):
            with self.assertRaisesRegex(setup.SetupError, "authorization expired"):
                setup.run_root(["must-not-run"])
        run_mock.assert_called_once_with(["sudo", "-n", "-v"], check=False)

    def test_mutations_require_configured_admin_and_prime_sudo(self):
        with mock.patch.object(setup, "current_username", return_value="root"):
            with self.assertRaisesRegex(setup.SetupError, "configured local administrator"):
                setup.require_setup_operator()

        with (
            mock.patch.object(setup, "current_username", return_value=setup.ADMIN_USER),
            mock.patch.object(setup, "run", return_value=setup.Completed(("sudo", "-v"), "", "")) as run_mock,
        ):
            setup.require_setup_operator()
        run_mock.assert_called_once_with(["sudo", "-v"], capture=False)

    def test_runtime_account_apply_preserves_omitted_existing_fields(self):
        args = setup.argparse.Namespace(
            username="alice",
            name=None,
            email=None,
            group=[],
            administrator=False,
            active=None,
            password_stdin=True,
            set_password=False,
        )
        current = {
            "username": "alice",
            "name": "Alice Existing",
            "email": "alice@nas.local",
            "active": True,
            "groups": ["nas_users", "nas_allow_files", "nas_allow_vault"],
            "attributes": {"nasSyncthingDevices": []},
        }
        captured = []

        def apply(plan):
            captured.append(json.loads(json.dumps(plan)))
            return {"created": [], "updated": ["alice"]}

        with (
            mock.patch.object(setup, "maintained_sudo_authorization", return_value=setup.contextlib.nullcontext()),
            mock.patch.object(setup, "existing_account", return_value=current),
            mock.patch.object(setup, "read_secret_stdin", return_value="new-password"),
            mock.patch.object(setup, "apply_accounts", side_effect=apply),
            mock.patch.object(setup, "provision_share_directories", return_value=[]),
        ):
            setup.one_account(args)

        account = captured[0]["accounts"][0]
        self.assertEqual(account["name"], "Alice Existing")
        self.assertEqual(account["email"], "alice@nas.local")
        self.assertEqual(
            account["groups"],
            ["nas_allow_files", "nas_allow_vault", "nas_users"],
        )
        self.assertEqual(account["attributes"], {"nasSyncthingDevices": []})
        self.assertEqual(account["password"], "new-password")

    def test_runtime_account_group_replacement_and_admin_addition_are_explicit(self):
        current = {
            "username": "alice",
            "name": "Alice",
            "email": "alice@nas.local",
            "active": True,
            "groups": ["nas_users", "nas_allow_files"],
            "attributes": {},
        }

        def invoke(groups, administrator=False):
            args = setup.argparse.Namespace(
                username="alice",
                name=None,
                email=None,
                group=groups,
                administrator=administrator,
                active=None,
                password_stdin=False,
                set_password=False,
            )
            captured = []
            with (
                mock.patch.object(setup, "maintained_sudo_authorization", return_value=setup.contextlib.nullcontext()),
                mock.patch.object(setup, "existing_account", return_value=current),
                mock.patch.object(
                    setup,
                    "apply_accounts",
                    side_effect=lambda plan: captured.append(json.loads(json.dumps(plan))) or {},
                ),
                mock.patch.object(setup, "provision_share_directories", return_value=[]),
            ):
                setup.one_account(args)
            return captured[0]["accounts"][0]["groups"]

        self.assertEqual(invoke(["nas_allow_vault"]), ["nas_allow_vault", "nas_users"])
        self.assertEqual(
            invoke([], administrator=True),
            ["nas_admin", "nas_allow_files", "nas_users"],
        )

    def test_runtime_disable_drops_reserved_groups_and_rejects_conflicting_flags(self):
        current = {
            "username": "alice",
            "name": "Alice",
            "email": "alice@nas.local",
            "active": True,
            "groups": ["nas_users", "nas_allow_files"],
            "attributes": {},
        }

        def invoke(groups):
            args = setup.argparse.Namespace(
                username="alice",
                name=None,
                email=None,
                group=groups,
                administrator=False,
                active=False,
                password_stdin=False,
                set_password=False,
            )
            captured = []
            with (
                mock.patch.object(setup, "maintained_sudo_authorization", return_value=setup.contextlib.nullcontext()),
                mock.patch.object(setup, "existing_account", return_value=current),
                mock.patch.object(
                    setup,
                    "apply_accounts",
                    side_effect=lambda plan: captured.append(json.loads(json.dumps(plan))) or {},
                ),
                mock.patch.object(setup, "provision_share_directories", return_value=[]),
            ):
                setup.one_account(args)
            return captured[0]["accounts"][0]["groups"]

        self.assertEqual(invoke([]), ["nas_disabled"])
        with self.assertRaisesRegex(setup.SetupError, "Do not combine"):
            invoke(["nas_allow_vault"])

    def test_inactive_accounts_drop_active_reserved_groups(self):
        raw = self.base()
        raw["accounts"][0]["active"] = False
        normalized = setup.normalize_config(raw)
        self.assertEqual(normalized["accounts"][0]["groups"], ["nas_disabled"])

    def test_state_writer_receives_password_free_report(self):
        report = {"accounts": {"created": ["alice"]}, "password": "must-not-survive"}
        calls = []
        staged_payloads = []

        def fake_run_root(command, **kwargs):
            calls.append(command)
            if command and command[0] == "install" and "0640" in command:
                staged_payloads.append(pathlib.Path(command[-2]).read_text())
            return setup.Completed(tuple(command), "", "")

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(setup, "STATE_PATH", pathlib.Path(tmp) / "state.json"),
            mock.patch.object(setup, "run_root", side_effect=fake_run_root),
        ):
            setup.write_state(report)
        self.assertEqual(len(staged_payloads), 1)
        self.assertNotIn("must-not-survive", staged_payloads[0])
        self.assertNotIn('"password"', staged_payloads[0])

    def test_prepare_first_start_publishes_missing_configuration_without_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "missing.json"
            status_path = pathlib.Path(tmp) / "status.json"
            state_path = pathlib.Path(tmp) / "state.json"
            with (
                mock.patch.object(setup, "FIRST_START_STATUS_PATH", status_path),
                mock.patch.object(setup, "STATE_PATH", state_path),
            ):
                result = setup.prepare_first_start(str(missing))
            self.assertEqual(result["status"], "configuration-missing")
            self.assertEqual(json.loads(status_path.read_text())["status"], "configuration-missing")

    def test_first_start_ready_state_contains_exact_storage_plan_but_no_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "first-run.json"
            config.write_text(
                json.dumps(
                    {
                        "storage": {
                            "createPool": True,
                            "devices": ["/dev/disk/by-id/disk-a", "/dev/disk/by-id/disk-b"],
                            "topology": "mirror",
                            "wipeDevices": True,
                        },
                        "accounts": [{"username": "alice", "groups": ["nas_allow_files"]}],
                        "features": {},
                        "runPreflight": True,
                    }
                )
            )
            with (
                mock.patch.object(setup, "STATE_PATH", pathlib.Path(tmp) / "state.json"),
                mock.patch.object(setup, "pool_exists", return_value=False),
            ):
                result = setup.first_start_status(str(config))
            self.assertEqual(result["status"], "ready")
            self.assertTrue(result["requiresDestructiveConfirmation"])
            self.assertEqual(result["storage"]["devices"], ["/dev/disk/by-id/disk-a", "/dev/disk/by-id/disk-b"])
            serialized = json.dumps(result)
            self.assertNotIn("passwordFile", serialized)
            self.assertNotIn("accounts", result)

    def test_cockpit_root_authorization_is_explicitly_scoped(self):
        with (
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.dict(setup.os.environ, {"NAS_SETUP_ALLOW_ROOT": "1"}, clear=False),
            mock.patch.object(setup, "progress"),
        ):
            setup.require_setup_operator()
        with (
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.dict(setup.os.environ, {}, clear=True),
            mock.patch.object(setup, "current_username", return_value="root"),
        ):
            with self.assertRaisesRegex(setup.SetupError, "configured local administrator"):
                setup.require_setup_operator()

    def test_setup_fingerprint_binds_password_values_without_storing_them(self):
        config = setup.normalize_config(
            {
                "storage": {"createPool": False},
                "features": {},
                "runPreflight": False,
                "accounts": [],
            }
        )
        args = mock.Mock(
            create_database=True,
            confirm_storage_device=[],
            allow_destructive_storage=False,
            skip_preflight=False,
        )
        first_plan = {"schemaVersion": 1, "accounts": [{"username": "alice", "password": "one"}]}
        second_plan = {"schemaVersion": 1, "accounts": [{"username": "alice", "password": "two"}]}
        first = setup.setup_fingerprint(config, args, first_plan, "master")
        second = setup.setup_fingerprint(config, args, second_plan, "master")
        self.assertNotEqual(first, second)
        self.assertNotIn("one", first)
        self.assertNotIn("two", second)
        self.assertEqual(
            first,
            setup.setup_fingerprint(config, args, first_plan, "master"),
        )

    def test_command_runner_bounds_environment_and_reports_failures(self):
        completed = mock.Mock(returncode=0, stdout="abcdefgh\n[output truncated]", stderr="stderr-v\n[output truncated]")
        with (
            mock.patch.object(setup, "COMMAND_MAX_OUTPUT_BYTES", 8),
            mock.patch.object(setup, "run_command", return_value=completed) as runner,
        ):
            result = setup.run(["tool", 7], input_text="secret\n", env={"EXTRA": 9}, timeout_seconds=3)
        self.assertEqual(result.command, ("tool", "7"))
        self.assertTrue(result.stdout.endswith("[output truncated]"))
        self.assertTrue(result.stderr.endswith("[output truncated]"))
        runner.assert_called_once_with(
            ("tool", "7"),
            input_text="secret\n",
            env={"EXTRA": 9},
            timeout_seconds=3,
            max_output_bytes=8,
            capture=True,
        )

        failed = mock.Mock(returncode=4, stdout="", stderr="specific failure")
        with mock.patch.object(setup, "run_command", return_value=failed):
            with self.assertRaisesRegex(setup.SetupError, "specific failure"):
                setup.run(["bad"])
            unchecked = setup.run(["bad"], check=False)
        self.assertEqual(unchecked.returncode, 4)

        timed_out = mock.Mock(returncode=124, stdout="", stderr="Command timed out")
        with mock.patch.object(setup, "run_command", return_value=timed_out):
            with self.assertRaisesRegex(setup.SetupError, "timed out after 2 seconds"):
                setup.run(["slow"], timeout_seconds=2)

    def test_privilege_command_adapters_cover_root_admin_and_expired_authorization(self):
        with mock.patch.object(setup, "current_username", return_value=setup.ADMIN_USER):
            self.assertEqual(setup.admin_command(["echo", 1]), ["echo", "1"])
        with (
            mock.patch.object(setup, "current_username", return_value="root"),
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.dict(setup.os.environ, {"PATH": "/test/bin"}, clear=True),
        ):
            command = setup.admin_command(["echo", "ok"])
        self.assertEqual(
            command[:6], ["runuser", "-u", setup.ADMIN_USER, "--", "env", f"HOME=/home/{setup.ADMIN_USER}"]
        )
        self.assertIn("PATH=/test/bin", command)
        with (
            mock.patch.object(setup, "current_username", return_value="mallory"),
            mock.patch.object(setup.os, "geteuid", return_value=1000),
        ):
            with self.assertRaisesRegex(setup.SetupError, "not mallory"):
                setup.admin_command(["true"])

        expected = setup.Completed(("true",), "", "")
        with (
            mock.patch.object(setup, "admin_command", return_value=["wrapped"]),
            mock.patch.object(setup, "run", return_value=expected) as runner,
        ):
            self.assertIs(setup.run_admin(["true"], capture=False), expected)
            runner.assert_called_once_with(["wrapped"], capture=False)

        with (
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.dict(setup.os.environ, {"NAS_SETUP_ALLOW_ROOT": "1"}, clear=True),
            mock.patch.object(setup, "run", return_value=expected) as runner,
        ):
            setup.run_interactive_privileged(["direct"])
            runner.assert_called_once_with(["direct"])
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "run_admin", return_value=expected) as runner,
        ):
            setup.run_interactive_privileged(["admin"])
            runner.assert_called_once_with(["admin"])

        with (
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.object(setup, "run", return_value=expected) as runner,
        ):
            setup.run_root(["root"])
            runner.assert_called_once_with(["root"])
        expired = setup.Completed(("sudo",), "", "expired", 1)
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "run", return_value=expired),
        ):
            with self.assertRaisesRegex(setup.SetupError, "authorization expired"):
                setup.run_root(["root"])
        refreshed = setup.Completed(("sudo",), "", "", 0)
        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "run", side_effect=[refreshed, expected]) as runner,
        ):
            self.assertIs(setup.run_root(["root"], capture=False), expected)
        self.assertEqual(runner.call_args_list[-1], mock.call(["sudo", "-n", "--", "root"], capture=False))

    def test_json_source_and_feature_catalog_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.json"
            path.write_text('{"value": 1}', encoding="utf-8")
            self.assertEqual(setup.read_json_source(str(path)), {"value": 1})
            with mock.patch.object(setup.sys, "stdin", io.StringIO('{"stdin": true}')):
                self.assertEqual(setup.read_json_source("-"), {"stdin": True})
            path.write_text("[1, 2]", encoding="utf-8")
            with self.assertRaisesRegex(setup.SetupError, "one object"):
                setup.read_json_source(str(path))
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(setup.SetupError, "Unable to read setup JSON"):
                setup.read_json_source(str(path))

        cases = [
            ("not-json", "invalid status JSON"),
            (json.dumps({"features": {}}), "no feature catalog"),
            (json.dumps({"features": [{"id": "known", "allowedModes": "on", "available": True}]}), "does not permit"),
        ]
        for output, message in cases:
            with (
                self.subTest(message=message),
                mock.patch.object(setup, "run_root", return_value=setup.Completed(("status",), output, "")),
            ):
                with self.assertRaisesRegex(setup.SetupError, message):
                    setup.validate_feature_request({"known": "on"})
        setup.validate_feature_request({})

    def test_keepass_database_verification_and_creation_are_postcondition_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = pathlib.Path(tmp) / "private" / "NAS.kdbx"
            database.parent.mkdir()
            database.write_text("existing", encoding="utf-8")
            with (
                mock.patch.object(setup, "KEEPASS_DATABASE", database),
                mock.patch.object(setup, "KEEPASS_KEY_FILE", "/key"),
                mock.patch.object(setup, "run_admin", return_value=setup.Completed(("db-info",), "", "")) as admin,
            ):
                self.assertEqual(setup.verify_or_create_database("password", create=False), "existing")
            self.assertIn("--key-file", admin.call_args.args[0])

            database.unlink()
            with mock.patch.object(setup, "KEEPASS_DATABASE", database):
                with self.assertRaisesRegex(setup.SetupError, "does not exist"):
                    setup.verify_or_create_database("password", create=False)

            def create(command, **_kwargs):
                database.write_text("created", encoding="utf-8")
                return setup.Completed(tuple(command), "", "")

            with (
                mock.patch.object(setup, "KEEPASS_DATABASE", database),
                mock.patch.object(setup, "KEEPASS_KEY_FILE", "/key"),
                mock.patch.object(setup, "run_root", return_value=setup.Completed(("install",), "", "")),
                mock.patch.object(setup, "run_admin", side_effect=create) as admin,
            ):
                self.assertEqual(setup.verify_or_create_database("password", create=True), "created")
            self.assertIn("--set-key-file", admin.call_args.args[0])

            database.unlink()
            with (
                mock.patch.object(setup, "KEEPASS_DATABASE", database),
                mock.patch.object(setup, "KEEPASS_KEY_FILE", ""),
                mock.patch.object(setup, "run_root", return_value=setup.Completed(("install",), "", "")),
                mock.patch.object(setup, "run_admin", return_value=setup.Completed(("db-create",), "", "")),
            ):
                with self.assertRaisesRegex(setup.SetupError, "did not create"):
                    setup.verify_or_create_database("password", create=True)

    def test_first_start_status_revalidates_completion_and_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = pathlib.Path(tmp) / "first-run.json"
            config_path.write_text(json.dumps({"storage": {"createPool": False}, "features": {}}))
            normalized = setup.normalize_config(json.loads(config_path.read_text()))
            digest = setup.setup_plan_digest(normalized)

            with (
                mock.patch.object(setup, "STATE_PATH", pathlib.Path(tmp) / "state.json"),
                mock.patch.object(setup, "load_json", side_effect=setup.JournalError("invalid state")),
            ):
                self.assertEqual(setup.first_start_status(str(config_path))["status"], "state-invalid")

            with (
                mock.patch.object(setup, "STATE_PATH", pathlib.Path(tmp) / "state.json"),
                mock.patch.object(setup, "load_json", return_value={"status": "complete", "planDigest": "old"}),
                mock.patch.object(setup, "validate_feature_request"),
            ):
                self.assertEqual(setup.first_start_status(str(config_path))["status"], "configuration-changed")

            state = {"status": "complete-unverified", "planDigest": digest, "completedAt": "now"}
            with (
                mock.patch.object(setup, "STATE_PATH", pathlib.Path(tmp) / "state.json"),
                mock.patch.object(setup, "load_json", return_value=state),
                mock.patch.object(setup, "validate_feature_request"),
                mock.patch.object(
                    setup, "setup_authority_health", return_value={"ok": False, "checks": {"pool": False}}
                ),
            ):
                result = setup.first_start_status(str(config_path))
            self.assertEqual(result["status"], "state-drift")

            with (
                mock.patch.object(setup, "STATE_PATH", pathlib.Path(tmp) / "state.json"),
                mock.patch.object(setup, "load_json", return_value=state),
                mock.patch.object(setup, "validate_feature_request"),
                mock.patch.object(setup, "setup_authority_health", return_value={"ok": True, "checks": {"pool": True}}),
            ):
                result = setup.first_start_status(str(config_path))
            self.assertEqual(result["status"], "complete-unverified")
            self.assertIn("without final preflight", result["message"])

    def test_first_start_job_rejects_multiline_password_and_cleans_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            request = root / "request.json"
            password = root / "password"
            token = "a" * 32
            job_id = "b" * 24
            request.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "jobId": job_id,
                        "reservationToken": token,
                        "config": "/etc/nixos/nixos-nas/first-run.json",
                        "planDigest": "c" * 64,
                        "devices": [],
                        "allowDestructiveStorage": False,
                        "confirmPasswordReapply": False,
                    }
                )
            )
            password.write_text("first\nsecond\n")
            os.chmod(request, 0o600)
            os.chmod(password, 0o600)
            with (
                mock.patch.object(setup, "STATE_PATH", root / "state.json"),
                mock.patch.object(setup, "cancel_reservation") as cancel,
            ):
                with self.assertRaisesRegex(setup.SetupError, "exactly one non-empty line"):
                    setup.run_first_start_job(request, password)
            cancel.assert_called_once_with(token)
            self.assertFalse(request.exists())
            self.assertFalse(password.exists())
            result = json.loads((root / "jobs" / f"{job_id}.json").read_text())
            self.assertEqual(result["status"], "failed")

    def test_first_start_job_reads_private_files_once_and_records_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            request = root / "request.json"
            password = root / "password"
            token = "d" * 32
            job_id = "e" * 24
            request.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "jobId": job_id,
                        "reservationToken": token,
                        "config": "/etc/nixos/nixos-nas/first-run.json",
                        "planDigest": "f" * 64,
                        "devices": ["/dev/disk/by-id/test"],
                        "allowDestructiveStorage": True,
                        "confirmPasswordReapply": True,
                    }
                )
            )
            password.write_text("secret\n")
            os.chmod(request, 0o600)
            os.chmod(password, 0o600)
            with (
                mock.patch.object(setup, "STATE_PATH", root / "state.json"),
                mock.patch.object(setup, "first_run", return_value={"status": "complete"}) as first_run,
                mock.patch.object(setup, "cancel_reservation") as cancel,
            ):
                result = setup.run_first_start_job(request, password)
            self.assertEqual(result, {"status": "complete"})
            args = first_run.call_args.args[0]
            self.assertEqual(args.keepass_password_value, "secret")
            self.assertEqual(args.reservation_token, token)
            self.assertTrue(args.allow_destructive_storage)
            cancel.assert_called_once_with(token)
            outcome = json.loads((root / "jobs" / f"{job_id}.json").read_text())
            self.assertEqual(outcome["status"], "complete")

    def test_secure_job_reader_rejects_symlink_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "target"
            target.write_text("value")
            os.chmod(target, 0o600)
            linked = root / "linked"
            linked.symlink_to(target)
            with self.assertRaisesRegex(setup.SetupError, "without following symlinks"):
                setup._read_secure_job_file(linked, "job", max_bytes=32)
            target.write_text("x" * 33)
            with self.assertRaisesRegex(setup.SetupError, "size limit"):
                setup._read_secure_job_file(target, "job", max_bytes=32)


if __name__ == "__main__":
    unittest.main()
