from __future__ import annotations

import email.message
import io
import json
import os
import pathlib
import pwd
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_setup as setup  # noqa: E402
import nas_setup_config as setup_config  # noqa: E402


class SetupApplicationRetirementTests(unittest.TestCase):
    def test_removal_uses_bootstrap_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = pathlib.Path(temporary) / "bootstrap-token"
            token_path.write_text("bootstrap-authority\n", encoding="utf-8")
            blueprint_path = pathlib.Path(temporary) / "nas-setup.yaml"
            blueprint_path.write_text("version: 1\n", encoding="utf-8")
            response = mock.MagicMock()
            response.__enter__.return_value.status = 204
            with (
                mock.patch.dict(os.environ, {"NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE": str(token_path)}),
                mock.patch.object(setup, "SETUP_BLUEPRINT_PATH", blueprint_path),
                mock.patch("urllib.request.urlopen", return_value=response) as urlopen,
            ):
                result = setup._remove_setup_application()
            self.assertFalse(blueprint_path.exists())

        self.assertEqual(result, {"removed": True, "slug": "nas-setup"})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer bootstrap-authority")

    def test_removal_fails_closed_when_bootstrap_authority_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = pathlib.Path(temporary) / "bootstrap-token"
            token_path.write_text("bootstrap-authority\n", encoding="utf-8")
            forbidden = urllib.error.HTTPError("http://authentik", 403, "Forbidden", email.message.Message(), None)
            with (
                mock.patch.dict(os.environ, {"NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE": str(token_path)}),
                mock.patch.object(setup, "SETUP_BLUEPRINT_PATH", pathlib.Path(temporary) / "nas-setup.yaml"),
                mock.patch("urllib.request.urlopen", side_effect=forbidden),
                self.assertRaisesRegex(setup.SetupError, "HTTP 403"),
            ):
                setup._remove_setup_application()
            forbidden.close()


class BootstrapAccountRetirementTests(unittest.TestCase):
    def test_persistent_bootstrap_environment_is_scrubbed_before_restart(self) -> None:
        calls: list[tuple[str, list[str]]] = []

        def record(kind: str):
            def invoke(command, **_kwargs):
                calls.append((kind, list(command)))
                return mock.Mock(returncode=0, stdout="", stderr="")

            return invoke

        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(setup, "current_coordination_token", return_value="a" * 32),
            mock.patch.object(setup, "run_root", side_effect=record("root")),
            mock.patch.object(setup, "run_admin", side_effect=record("admin")),
            mock.patch.object(setup, "run_interactive_privileged", side_effect=record("activate")),
        ):
            result = setup.retire_bootstrap_runtime(pathlib.Path(temporary), "nasadmin", "keepass-password")

        self.assertEqual(result, {"bootstrapRetired": True})
        actions = [(kind, " ".join(command)) for kind, command in calls]
        retire_user = next(index for index, item in enumerate(actions) if "retire-bootstrap nasadmin" in item[1])
        retire_secret = next(
            index for index, item in enumerate(actions) if "retire-authentik-bootstrap-stdin" in item[1]
        )
        scrub_environment = next(index for index, item in enumerate(actions) if "/^AUTHENTIK_BOOTSTRAP_/d" in item[1])
        activate = next(index for index, item in enumerate(actions) if "activate-stdin" in item[1])
        self.assertLess(retire_user, retire_secret)
        self.assertLess(retire_secret, scrub_environment)
        self.assertLess(scrub_environment, activate)


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

    def test_vm_first_run_fixtures_use_the_current_config_shape(self) -> None:
        for relative in ("tests/vm/guest-test.sh", "tests/vm/encrypted-guest-test.sh"):
            content = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn('"features":', content, relative)
            self.assertNotIn('"schemaVersion": 1,\n  "storage"', content, relative)
            self.assertNotIn('{"schemaVersion":1,"storage"', content, relative)
            self.assertNotIn('"groups": ["nas_admin", "nas_allow_', content, relative)
            self.assertNotIn('"groups": ["nas_users", "nas_allow_', content, relative)

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
        with self.assertRaisesRegex(setup_config.SetupError, "always, off, on-demand"):
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


class StorageProvisioningTests(unittest.TestCase):
    def test_pool_creation_uses_a_short_lived_device_helper_for_future_zfs_partitions(self) -> None:
        calls: list[list[str]] = []

        def capture(command, **_kwargs):
            calls.append(list(command))
            output = "off\n" if "encryption" in command else ""
            return setup.Completed(tuple(command), output, "")

        with (
            mock.patch.object(setup, "pool_exists", return_value=False),
            mock.patch.object(setup, "dataset_exists", return_value=True),
            mock.patch.object(setup, "validate_storage_request"),
            mock.patch.object(setup, "run_root", side_effect=capture),
            mock.patch.object(setup.secrets, "token_hex", return_value="0123456789abcdef"),
        ):
            result = setup.setup_storage(
                {
                    "createPool": True,
                    "devices": ["/dev/disk/by-id/confirmed"],
                    "topology": "single",
                    "ashift": 12,
                    "wipeDevices": False,
                },
                keepass_password="unused",
                confirmed_devices=["/dev/disk/by-id/confirmed"],
                allow_destructive=True,
                encrypt_storage=False,
            )

        helper = calls[0]
        self.assertEqual(helper[:2], ["systemd-run", "--quiet"])
        self.assertIn("--wait", helper)
        self.assertIn("--collect", helper)
        self.assertIn("--property=PrivateDevices=no", helper)
        self.assertIn("--property=DevicePolicy=auto", helper)
        self.assertIn("--setenv=NAS_SETUP_ALLOW_ROOT=1", helper)
        self.assertFalse(any(value.startswith("--property=Protect") for value in helper))
        self.assertEqual(
            helper[helper.index("--") + 1 : -2],
            [
                "zpool",
                "create",
                "-f",
                "-o",
                "ashift=12",
                "-O",
                "compression=zstd",
                "-O",
                "atime=off",
                "-O",
                "xattr=sa",
                "-O",
                "acltype=posixacl",
                "-O",
                "mountpoint=none",
                "-m",
                "none",
            ],
        )
        self.assertEqual(helper[-2:], [setup.ZFS_POOL, "/dev/disk/by-id/confirmed"])
        self.assertEqual(
            calls[2][calls[2].index("--") + 1 :],
            ["zfs", "get", "-H", "-o", "value", "encryption", setup.ZFS_DATASET],
        )
        self.assertEqual(calls[3][calls[3].index("--") + 1 :], ["zfs", "mount", setup.ZFS_DATASET])
        self.assertEqual(calls[4][calls[4].index("--") + 1 :], ["nas-zfs-mount-check"])
        self.assertTrue(result["createdPool"])

    def test_encryption_toggle_creates_the_dataset_through_the_keepass_backed_helper(self) -> None:
        calls: list[tuple[list[str], str | None, bool]] = []

        def capture(command, *, input_text=None, check=True, **_kwargs):
            calls.append((list(command), input_text, check))
            return setup.Completed(tuple(command), "", "")

        with (
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup, "dataset_exists", return_value=False),
            mock.patch.object(setup, "run_storage_host", side_effect=capture),
        ):
            result = setup.setup_storage(
                {"createPool": False},
                keepass_password="database-password",
                confirmed_devices=[],
                allow_destructive=False,
                encrypt_storage=True,
            )

        self.assertEqual(calls, [(["nas-zfs-create-encrypted-dataset"], "database-password\n", True)])
        self.assertTrue(result["createdDataset"])
        self.assertTrue(result["encrypted"])

    def test_existing_dataset_must_match_the_reviewed_encryption_toggle(self) -> None:
        for encryption_value, selected in (("off\n", True), ("aes-256-gcm\n", False)):
            with (
                self.subTest(encryption_value=encryption_value, selected=selected),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "dataset_exists", return_value=True),
                mock.patch.object(
                    setup,
                    "run_storage_host",
                    return_value=setup.Completed(("zfs", "get"), encryption_value, ""),
                ) as run_storage,
            ):
                with self.assertRaisesRegex(setup.SetupError, "does not match the encryption choice"):
                    setup.setup_storage(
                        {"createPool": False},
                        keepass_password="database-password",
                        confirmed_devices=[],
                        allow_destructive=False,
                        encrypt_storage=selected,
                    )
            self.assertEqual(run_storage.call_count, 1)

    def test_storage_runtime_unlocks_only_when_encryption_was_selected(self) -> None:
        for selected in (True, False):
            with (
                self.subTest(selected=selected),
                mock.patch.object(setup, "coordinated_child", side_effect=lambda command: list(command)),
                mock.patch.object(setup, "run_interactive_privileged") as activate,
                mock.patch.object(setup, "run_storage_host", return_value=setup.Completed((), "", "")) as storage,
            ):
                self.assertEqual(
                    setup.prepare_storage_runtime("database-password", selected),
                    {"mounted": True, "runtimeDirectoriesPrepared": True},
                )
            self.assertEqual(activate.call_count, int(selected))
            if selected:
                self.assertEqual(activate.call_args.kwargs["input_text"], "database-password\n")
            self.assertEqual(storage.call_args_list[0].args[0], ["nas-zfs-mount-check"])
            self.assertEqual(
                storage.call_args_list[1].args[0],
                ["systemd-tmpfiles", "--create", "--prefix", str(setup.ZFS_ROOT / "nas-control")],
            )


class LocalAdministratorTests(unittest.TestCase):
    def test_first_run_creates_keepass_before_storage_and_regenerates_identity_afterward(self) -> None:
        source = (SERVICES / "nas_setup.py").read_text(encoding="utf-8")
        workflow = source.split("def _first_run_locked", 1)[1].split("def existing_account", 1)[0]
        keepass = workflow.index('"keepass-database"')
        storage = workflow.index('"storage",', keepass)
        self.assertLess(keepass, storage)
        self.assertLess(storage, workflow.index('"identity-database-regeneration"'))

    def test_setup_rejects_the_disposable_bootstrap_name_for_the_permanent_account(self) -> None:
        with self.assertRaisesRegex(setup.SetupError, "reserved bootstrap"):
            setup.local_administrator_details({"username": "akadmin"})

    def test_setup_creates_a_user_chosen_linux_administrator_without_password_arguments(self) -> None:
        calls: list[tuple[list[str], str | None]] = []
        account = pwd.struct_passwd(("nasadmin", "x", 1002, 100, "", "/tank/homes/nasadmin", "/bin/bash"))

        def capture(command, *, input_text=None, **_kwargs):
            calls.append((list(command), input_text))
            if command[:3] == ["id", "--user", "nasadmin"]:
                return setup.Completed(tuple(command), "", "", 1)
            return setup.Completed(tuple(command), "", "")

        with (
            mock.patch.object(setup, "run_root", side_effect=capture),
            mock.patch.object(setup.pwd, "getpwnam", return_value=account),
            mock.patch.object(setup, "LOCAL_HOME_ROOT", pathlib.Path("/tank/homes")),
        ):
            result = setup.create_local_administrator(
                {"username": "nasadmin", "name": "NAS Administrator", "email": "admin@example.test"},
                "new-local-password",
            )

        self.assertEqual(result["username"], "nasadmin")
        self.assertEqual(result["groups"], ["nas_admin"])
        self.assertIn(
            (
                [
                    "useradd",
                    "--home-dir",
                    "/tank/homes/nasadmin",
                    "--no-create-home",
                    "--shell",
                    "/run/current-system/sw/bin/bash",
                    "nasadmin",
                ],
                None,
            ),
            calls,
        )
        self.assertIn((["install", "-d", "-m", "0711", "-o", "root", "-g", "root", "/tank/homes"], None), calls)
        self.assertIn(
            (["install", "-d", "-m", "0700", "-o", "1002", "-g", "100", "/tank/homes/nasadmin"], None),
            calls,
        )
        self.assertIn((["chpasswd"], "nasadmin:new-local-password\n"), calls)
        self.assertIn(
            (["usermod", "--append", "--groups", "wheel,nas-administrators,nas-operations", "nasadmin"], None), calls
        )
        self.assertTrue(all("new-local-password" not in " ".join(command) for command, _input in calls))

    def test_setup_recovers_a_missing_zfs_home_from_a_partial_useradd(self) -> None:
        calls: list[list[str]] = []
        account = pwd.struct_passwd(("nasadmin", "x", 1002, 100, "", "/tank/homes/nasadmin", "/bin/bash"))

        def capture(command, **_kwargs):
            calls.append(list(command))
            return setup.Completed(tuple(command), "", "", 0)

        with (
            mock.patch.object(setup, "run_root", side_effect=capture),
            mock.patch.object(setup.pwd, "getpwnam", return_value=account),
            mock.patch.object(setup, "LOCAL_HOME_ROOT", pathlib.Path("/tank/homes")),
        ):
            setup.create_local_administrator(
                {"username": "nasadmin", "name": "NAS Administrator", "email": "admin@example.test"},
                "new-local-password",
            )

        self.assertIn(
            ["install", "-d", "-m", "0700", "-o", "1002", "-g", "100", "/tank/homes/nasadmin"],
            calls,
        )
        self.assertFalse(any(command[:1] == ["systemd-run"] for command in calls))

    def test_root_runs_administrator_commands_with_the_zfs_passwd_home(self) -> None:
        account = pwd.struct_passwd(("nasadmin", "x", 1002, 100, "", "/tank/homes/nasadmin", "/bin/bash"))
        with (
            mock.patch.object(setup, "local_administrator_username", return_value="nasadmin"),
            mock.patch.object(setup, "current_username", return_value="root"),
            mock.patch.object(setup.os, "geteuid", return_value=0),
            mock.patch.object(setup.pwd, "getpwnam", return_value=account),
        ):
            command = setup.admin_command(["nas-secrets", "init"])
        self.assertIn("HOME=/tank/homes/nasadmin", command)
        self.assertIn("--chdir=/tank/homes/nasadmin", command)
        self.assertNotIn("HOME=/home/nasadmin", command)

    def test_finalizing_local_administrator_removes_bootstrap_and_persists_only_username(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / "administrator.json"
            with (
                mock.patch.object(setup, "ADMIN_STATE_PATH", state),
                mock.patch.object(setup, "run_root", return_value=setup.Completed((), "", "")) as run_root,
            ):
                result = setup.finalize_local_administrator({"username": "nasadmin"})
                persisted = json.loads(state.read_text(encoding="utf-8"))
        self.assertEqual(result, {"username": "nasadmin"})
        retirement = run_root.call_args_list[2].args[0]
        cleanup = run_root.call_args_list[3].args[0]
        self.assertEqual(retirement[:1], ["systemd-run"])
        self.assertIn("--property=ProtectHome=read-only", retirement)
        self.assertEqual(retirement[retirement.index("--") + 1 :], ["userdel", "akadmin"])
        self.assertIn("--property=ProtectHome=no", cleanup)
        self.assertIn("--property=ReadWritePaths=/home", cleanup)
        self.assertEqual(
            cleanup[cleanup.index("--") + 1 :],
            ["rm", "--recursive", "--force", "--one-file-system", "--", "/home/akadmin"],
        )
        self.assertEqual(persisted, {"username": "nasadmin"})

    def test_finalizing_local_administrator_cleans_partial_bootstrap_retirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / "administrator.json"
            with (
                mock.patch.object(setup, "ADMIN_STATE_PATH", state),
                mock.patch.object(
                    setup,
                    "run_root",
                    side_effect=[
                        setup.Completed(("chown",), "", ""),
                        setup.Completed(("id",), "", "", 1),
                        setup.Completed(("rm",), "", ""),
                    ],
                ) as run_root,
            ):
                setup.finalize_local_administrator({"username": "nasadmin"})
        self.assertEqual(len(run_root.call_args_list), 3)
        cleanup = run_root.call_args_list[2].args[0]
        self.assertEqual(cleanup[cleanup.index("--") + 1 :][-1], "/home/akadmin")

    def test_control_plane_authorities_are_boot_side_and_never_zfs_promoted(self) -> None:
        self.assertEqual(setup.BOOTSTRAP_RUNTIME_ROOT, pathlib.Path("/var/lib/nas-control-plane"))
        self.assertTrue(setup.KEEPASS_DATABASE.is_relative_to(setup.BOOTSTRAP_RUNTIME_ROOT))
        source = (SERVICES / "nas_setup.py").read_text(encoding="utf-8")
        self.assertNotIn("promote_bootstrap_runtime", source)
        self.assertNotIn("operational-runtime-select", source)

    def test_identity_database_regeneration_preserves_boot_side_keepass(self) -> None:
        calls: list[list[str]] = []

        def capture(command, **_kwargs):
            calls.append(list(command))
            return setup.Completed(tuple(command), "", "")

        with tempfile.TemporaryDirectory() as raw:
            control = pathlib.Path(raw)
            for name in ("authentik", "postgresql", "nas-secrets"):
                (control / name).mkdir()
            database = control / "nas-secrets/NAS.kdbx"
            database.write_text("keep", encoding="utf-8")
            with mock.patch.object(setup, "run_root", side_effect=capture):
                result = setup.regenerate_boot_identity_databases(control)

        self.assertEqual(result, {"regenerated": True, "bootSide": True})
        self.assertIn(["find", str(control / "authentik"), "-mindepth", "1", "-delete"], calls)
        self.assertIn(["find", str(control / "postgresql"), "-mindepth", "1", "-delete"], calls)
        self.assertFalse(any(str(control / "nas-secrets") in command for command in calls))


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
        def fake_exists(path: pathlib.Path) -> bool:
            return path == setup.KEEPASS_DATABASE

        with (
            mock.patch.object(pathlib.Path, "exists", autospec=True, side_effect=fake_exists),
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup, "dataset_exists", return_value=True),
        ):
            result = setup.status_report()
        self.assertNotIn("features", result)


class FirstStartJobTests(unittest.TestCase):
    def test_rejects_non_string_keepass_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            request_file = root / "request.json"
            password_file = root / "password.json"
            request_file.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "jobId": "a" * 24,
                        "reservationToken": "b" * 32,
                        "config": "/tmp/config.json",
                        "planDigest": "c" * 64,
                        "devices": [],
                        "allowDestructiveStorage": False,
                        "encryptStorage": True,
                        "confirmPasswordReapply": False,
                    }
                ),
                encoding="utf-8",
            )
            password_file.write_text(
                json.dumps(
                    {
                        "keepass": None,
                        "administrator": {
                            "username": "nasadmin",
                            "name": "NAS Administrator",
                            "email": "admin@example.test",
                            "password": "password",
                        },
                    }
                ),
                encoding="utf-8",
            )
            request_file.chmod(0o600)
            password_file.chmod(0o600)
            with (
                mock.patch.object(setup, "STATE_PATH", root / "state.json"),
                mock.patch.object(setup, "cancel_reservation"),
            ):
                with self.assertRaisesRegex(setup.SetupError, "KeePass database password is invalid"):
                    setup.run_first_start_job(request_file, password_file)


class ConfiguredAdministratorTests(unittest.TestCase):
    def test_uses_the_unique_passworded_admin_account(self) -> None:
        plan = {
            "accounts": [
                {"username": "alice", "active": True, "groups": ["nas_users"], "password": "alice-password"},
                {"username": "operator", "active": True, "groups": ["nas_admin"], "password": "operator-password"},
            ]
        }
        administrator = setup.configured_administrator(plan)
        self.assertIsNotNone(administrator)
        assert administrator is not None
        self.assertEqual(administrator["username"], "operator")

    def test_requires_one_passworded_admin_account(self) -> None:
        self.assertIsNone(setup.configured_administrator({"accounts": []}))
        self.assertIsNone(
            setup.configured_administrator(
                {
                    "accounts": [
                        {"username": "one", "active": True, "groups": ["nas_admin"], "password": "one-password"},
                        {"username": "two", "active": True, "groups": ["nas_admin"], "password": "two-password"},
                    ]
                }
            )
        )

    def test_replaces_the_matching_planned_account(self) -> None:
        plan = {"accounts": [{"username": "operator", "groups": ["nas_admin"], "password": "old"}]}
        setup.include_local_administrator(
            plan,
            {
                "username": "operator",
                "name": "Operator",
                "email": "operator@nas.local",
                "active": True,
                "groups": ["nas_admin"],
                "attributes": {},
            },
            "new-password",
        )
        self.assertEqual(len(plan["accounts"]), 1)
        self.assertEqual(plan["accounts"][0]["password"], "new-password")

    def test_existing_keepass_database_checks_follow_directory_ownership_setup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = pathlib.Path(tmp) / "secrets" / "NAS.kdbx"
            database.parent.mkdir()
            database.write_text("fixture", encoding="utf-8")
            with (
                mock.patch.object(setup, "KEEPASS_DATABASE", database),
                mock.patch.object(setup, "run_root") as run_root,
                mock.patch.object(setup, "run_admin") as run_admin,
            ):
                self.assertEqual(setup.verify_or_create_database("password", True), "existing")
        self.assertEqual(run_root.call_args.args[0][0], "install")
        self.assertEqual(run_admin.call_args.args[0][0], "keepassxc-cli")


class CliTests(unittest.TestCase):
    def test_validate_config_cli_outputs_schema_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.json"
            path.write_text(
                json.dumps({"schemaVersion": 2, "storage": {"createPool": False}, "accounts": [], "services": {}}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(sys, "argv", ["nas-setup", "validate-config", str(path)]),
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                self.assertEqual(setup.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue())["schemaVersion"], 2)


if __name__ == "__main__":
    unittest.main()
