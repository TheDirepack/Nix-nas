from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import pwd
import sys
import subprocess
import tempfile
import unittest
from typing import Any
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_setup as setup  # noqa: E402
import nas_setup_config as setup_config  # noqa: E402


class SetupApplicationRetirementTests(unittest.TestCase):
    def retire(self, stdout: str) -> tuple[dict[str, object] | None, mock.Mock, pathlib.Path, BaseException | None]:
        with tempfile.TemporaryDirectory() as temporary:
            blueprint_path = pathlib.Path(temporary) / "nas-setup.yaml"
            blueprint_path.write_text("version: 1\n", encoding="utf-8")
            completed = setup.Completed(("nas-identity-sync",), stdout, "")
            error: BaseException | None = None
            result = None
            with (
                mock.patch.object(setup, "SETUP_BLUEPRINT_PATH", blueprint_path),
                mock.patch.object(setup, "coordinated_child", side_effect=lambda command: ["env", *command]),
                mock.patch.object(setup, "run_root", return_value=completed) as run_root,
            ):
                try:
                    result = setup.retire_setup_application()
                except setup.SetupError as exc:
                    error = exc
            self.assertFalse(blueprint_path.exists(), "the blueprint must not recreate the application")
            return result, run_root, blueprint_path, error

    def test_retirement_uses_the_identity_sync_authentik_client(self) -> None:
        proof = {"absent": True, "removed": True, "slug": "nas-setup"}
        result, run_root, _blueprint, error = self.retire(json.dumps(proof))
        self.assertIsNone(error)
        self.assertEqual(result, proof)
        run_root.assert_called_once_with(["env", "nas-identity-sync", "retire-setup-application"])

    def test_retirement_rejects_output_without_canonical_absence_proof(self) -> None:
        for stdout in ('{"removed": false, "reason": "not-found"}', '{"slug": "nas-setup"}', "[]", "not-json"):
            with self.subTest(stdout=stdout):
                _result, _run_root, _blueprint, error = self.retire(stdout)
                self.assertIsInstance(error, setup.SetupError)

    def test_resumed_journal_does_not_trust_a_legacy_not_found_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "journal.json"
            journal = setup.OperationJournal.open(path, workflow="first-run-v2", fingerprint="f" * 64)
            journal.complete_step("setup-application-retirement", {"removed": False, "reason": "not-found"})
            action = mock.Mock()
            with self.assertRaisesRegex(setup.SetupError, "explicit recovery"):
                setup.run_setup_stage(
                    journal, "setup-application-retirement", action, postcondition=setup.setup_application_retired
                )
            action.assert_not_called()
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["status"], "manual-recovery-required")

    def test_resumed_journal_accepts_recorded_deletions(self) -> None:
        for recorded in (
            {"removed": True, "slug": "nas-setup"},
            {"absent": True, "removed": False, "slug": "nas-setup"},
        ):
            with self.subTest(recorded=recorded), tempfile.TemporaryDirectory() as temporary:
                journal = setup.OperationJournal.open(
                    pathlib.Path(temporary) / "journal.json", workflow="first-run-v2", fingerprint="f" * 64
                )
                journal.complete_step("setup-application-retirement", recorded)
                action = mock.Mock()
                result = setup.run_setup_stage(
                    journal, "setup-application-retirement", action, postcondition=setup.setup_application_retired
                )
                self.assertEqual(result, recorded)
                action.assert_not_called()


class BootstrapAuthentikPasswordTests(unittest.TestCase):
    def test_first_boot_generates_password_outside_the_nix_store(self) -> None:
        application = (ROOT / "modules/nas/config/application-services.nix").read_text()
        services = (ROOT / "modules/nas/internal/secret-tools.nix").read_text()
        self.assertIn("openssl rand -hex 24", application)
        self.assertIn("AUTHENTIK_BOOTSTRAP_PASSWORD=", application)
        self.assertIn('requires = [ "nas-bootstrap-authentik-secrets.service" ]', application)
        self.assertIn("Missing secure first-boot Authentik password", application)
        self.assertIn('store_value authentik-bootstrap-password "$bootstrap_password"', services)
        self.assertNotIn("store_value authentik-bootstrap-password ${lib.escapeShellArg bootstrapPassword}", services)

    def test_vm_browser_does_not_reuse_the_linux_bootstrap_password(self) -> None:
        guest = (ROOT / "tests/vm/guest-test.sh").read_text(encoding="utf-8")
        self.assertIn("bootstrap_authentik_password", guest)
        self.assertIn("^AUTHENTIK_BOOTSTRAP_PASSWORD=//p", guest)
        self.assertIn('"$bootstrap_authentik_password" > "$bootstrap_authz_secret_dir/akadmin"', guest)
        self.assertIn('"$bootstrap_authentik_password" >"$wizard_secret_dir/akadmin"', guest)
        self.assertNotIn("'nas-admin-first-boot' > \"$bootstrap_authz_secret_dir/akadmin\"", guest)
        self.assertNotIn("'nas-admin-first-boot' >\"$wizard_secret_dir/akadmin\"", guest)

    def test_bootstrap_adoption_carries_the_actual_runtime_password(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            environment = root / "environment"
            token = root / "api-token"
            secret = "a" * 128
            password = "b" * 48
            environment.write_text(
                f"AUTHENTIK_SECRET_KEY={secret}\nAUTHENTIK_BOOTSTRAP_PASSWORD={password}\n",
                encoding="utf-8",
            )
            token.write_text("c" * 64, encoding="utf-8")
            with (
                mock.patch.object(setup, "BOOTSTRAP_AUTHENTIK_ENVIRONMENT", environment),
                mock.patch.object(setup, "BOOTSTRAP_AUTHENTIK_TOKEN", token),
                mock.patch.object(setup, "coordinated_child", side_effect=lambda command: command),
                mock.patch.object(setup, "run_admin") as adopt,
                mock.patch.object(setup, "runtime_secrets_ready", return_value=False),
            ):
                self.assertEqual(setup.adopt_bootstrap_authentik_authority("db-pass"), {"adopted": True})
            self.assertEqual(
                adopt.call_args.kwargs["input_text"],
                f"db-pass\n{secret}\n{'c' * 64}\n{password}\n",
            )

    def test_bootstrap_adoption_fails_closed_without_password(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            environment = root / "environment"
            token = root / "api-token"
            environment.write_text(f"AUTHENTIK_SECRET_KEY={'a' * 128}\n", encoding="utf-8")
            token.write_text("c" * 64, encoding="utf-8")
            with (
                mock.patch.object(setup, "BOOTSTRAP_AUTHENTIK_ENVIRONMENT", environment),
                mock.patch.object(setup, "BOOTSTRAP_AUTHENTIK_TOKEN", token),
                mock.patch.object(setup, "run_admin") as adopt,
            ):
                with self.assertRaisesRegex(setup.SetupError, "password is missing or malformed"):
                    setup.adopt_bootstrap_authentik_authority("db-pass")
            adopt.assert_not_called()


class SyncthingSetupTests(unittest.TestCase):
    def test_sync_starts_syncthing_and_waits_for_its_api(self) -> None:
        connection = mock.MagicMock()
        identity_result = setup.Completed(("nas-identity-sync",), '{"folders": 1}', "")

        def run_root(command, **_kwargs):
            if command[:2] == ["systemctl", "start"]:
                return setup.Completed(tuple(command), "", "")
            return identity_result

        with (
            mock.patch.object(setup, "run_root", side_effect=run_root) as root,
            mock.patch.object(setup, "current_coordination_token", return_value="a" * 32),
            mock.patch.object(
                setup.socket,
                "create_connection",
                side_effect=[ConnectionRefusedError(), connection],
            ) as create_connection,
            mock.patch.object(setup.time, "sleep") as sleep,
        ):
            result = setup.sync_syncthing_for_setup()

        self.assertEqual(result, {"folders": 1})
        self.assertEqual(root.call_args_list[0].args[0], ["systemctl", "start", "syncthing.service"])
        self.assertIn("sync-syncthing", root.call_args_list[1].args[0])
        self.assertEqual(create_connection.call_count, 2)
        connection.close.assert_called_once_with()
        sleep.assert_called_once()


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
            "services": {"syncthing": "on-demand"},
            "runPreflight": True,
        }

    def test_config_is_v2_native_and_rejects_features(self) -> None:
        value = setup_config.normalize_config(self.base())
        self.assertEqual(value["schemaVersion"], 2)
        self.assertEqual(value["services"], {"syncthing": "on-demand"})
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
            self.assertNotIn("nas_allow_", content, relative)

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
        bad["services"] = {"syncthing": "sometimes"}
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
                    "id": "syncthing",
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
            setup.validate_service_request({"syncthing": "on-demand"})
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
            result = setup.apply_services({"syncthing": "always"})
        self.assertEqual(result, {"syncthing": "always"})
        command = run_root.call_args.args[0]
        self.assertIn("nas-managed-services-control", command)
        self.assertNotIn("nas-feature-control", command)
        self.assertEqual(command[-2:], ["set-many", "-"])

    def test_service_policy_ready_reads_requested_modes(self) -> None:
        with mock.patch.object(setup, "_managed_services_status", return_value=self.service_status()):
            self.assertTrue(setup.service_policy_ready({"syncthing": "on-demand"}))
            self.assertFalse(setup.service_policy_ready({"syncthing": "always"}))

    def test_canonical_plan_contains_services_not_features(self) -> None:
        config = setup_config.normalize_config(
            {
                "schemaVersion": 2,
                "storage": {"createPool": False},
                "accounts": [],
                "services": {"syncthing": "on-demand"},
                "runPreflight": False,
            }
        )
        plan = setup.canonical_setup_plan(config)
        self.assertEqual(plan["services"], {"syncthing": "on-demand"})
        self.assertNotIn("features", plan)
        self.assertRegex(setup.setup_plan_digest(config), r"^[0-9a-f]{64}$")


class ShareProvisioningTests(unittest.TestCase):
    def test_backing_directories_are_not_application_authorization_state(self) -> None:
        accounts = [
            {"username": "alice", "active": True, "groups": ["nas_users"]},
            {"username": "admin2", "active": True, "groups": ["nas_admin"]},
            {"username": "guest", "active": True, "groups": ["nas_guests"]},
            {"username": "disabled", "active": False, "groups": ["nas_disabled"]},
            {"username": "truthy", "active": 1, "groups": ["nas_users"]},
            {"username": "missing", "groups": ["nas_users"]},
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

    def test_readiness_checks_only_eligible_personal_directories(self) -> None:
        accounts = [
            {"username": "alice", "active": True, "groups": ["nas_users"]},
            {"username": "guest", "active": True, "groups": ["nas_guests"]},
            {"username": "disabled", "active": False},
            {"username": "truthy", "active": 1},
            {"username": "missing"},
        ]
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(setup, "SHARE_ROOT", pathlib.Path(tmp)),
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(
                setup, "run_root_noninteractive", return_value=setup.Completed((), "directory\n", "")
            ) as probe,
        ):
            self.assertTrue(setup.share_directories_ready(accounts))
            probe.assert_called_once_with(["stat", "-c", "%F", str(pathlib.Path(tmp) / "users/alice")], check=False)
            probe.return_value = setup.Completed((), "symbolic link\n", "")
            self.assertFalse(setup.share_directories_ready(accounts))

    def test_root_readiness_rejects_missing_directories_and_symlinks(self) -> None:
        accounts = [{"username": "alice", "active": True}]
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(setup, "SHARE_ROOT", pathlib.Path(tmp)),
            mock.patch.object(setup.os, "geteuid", return_value=0),
        ):
            path = pathlib.Path(tmp) / "users/alice"
            path.parent.mkdir()
            self.assertFalse(setup.share_directories_ready(accounts))
            path.mkdir()
            self.assertTrue(setup.share_directories_ready(accounts))
            path.rmdir()
            path.symlink_to(path.parent, target_is_directory=True)
            self.assertFalse(setup.share_directories_ready(accounts))


class StorageProvisioningTests(unittest.TestCase):
    def test_in_use_storage_is_rejected_before_any_destructive_command(self):
        inventory = {
            "blockdevices": [
                {
                    "path": "/dev/sda",
                    "maj:min": "8:0",
                    "type": "disk",
                    "mountpoints": [None],
                    "children": [{"path": "/dev/sda1", "maj:min": "8:1", "type": "part", "mountpoints": ["/"]}],
                }
            ]
        }
        for mounts, swaps in ((["/"], ""), (["/boot"], ""), ([None], "/dev/sda1 partition 10 0 -2\n")):
            inventory["blockdevices"][0]["children"][0]["mountpoints"] = mounts

            def command(argv, **kwargs):
                if argv[0] == "lsblk":
                    return setup.Completed(tuple(argv), json.dumps(inventory), "")
                if argv[0] == "cat":
                    return setup.Completed(tuple(argv), "Filename Type Size Used Priority\n" + swaps, "")
                self.fail(f"unexpected destructive command: {argv}")

            with (
                self.subTest(mounts=mounts, swaps=swaps),
                mock.patch.object(setup, "pool_exists", return_value=False),
                mock.patch.object(setup.os, "stat", return_value=mock.Mock(st_mode=0o60600, st_rdev=os.makedev(8, 0))),
                mock.patch.object(setup, "run_storage_host", side_effect=command),
            ):
                with self.assertRaisesRegex(setup.SetupError, "in use"):
                    setup.setup_storage(
                        {"createPool": True, "devices": ["/dev/sda"], "wipeDevices": True},
                        keepass_password="unused",
                        confirmed_devices=["/dev/sda"],
                        allow_destructive=True,
                    )

    def test_uninspectable_storage_fails_closed(self):
        with (
            mock.patch.object(setup, "pool_exists", return_value=False),
            mock.patch.object(setup.os, "stat", return_value=mock.Mock(st_mode=0o60600, st_rdev=os.makedev(8, 0))),
            mock.patch.object(setup, "run_storage_host", return_value=setup.Completed((), "{}", "")),
        ):
            with self.assertRaisesRegex(setup.SetupError, "inventory"):
                setup.validate_storage_request({"createPool": True, "devices": ["/dev/sda"]}, ["/dev/sda"], True)

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
            mock.patch.object(setup, "validate_unused_devices"),
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
                mock.patch.object(setup, "run_root") as root,
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
                ["systemd-tmpfiles", "--create", "--graceful"],
            )
            if selected:
                self.assertEqual(
                    [call.args[0] for call in root.call_args_list],
                    [
                        ["systemctl", "start", "nas-zfs-unlock.service"],
                        ["systemctl", "restart", "nas-managed-services-seed.service"],
                    ],
                )
            else:
                root.assert_called_once_with(["systemctl", "restart", "nas-managed-services-seed.service"])


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
        state_chown = run_root.call_args_list[1].args[0]
        self.assertEqual(state_chown, ["chown", "nasadmin:users", str(state)])
        retirement = run_root.call_args_list[3].args[0]
        cleanup = run_root.call_args_list[4].args[0]
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
                        setup.Completed(("chown",), "", ""),
                        setup.Completed(("id",), "", "", 1),
                        setup.Completed(("rm",), "", ""),
                    ],
                ) as run_root,
            ):
                setup.finalize_local_administrator({"username": "nasadmin"})
        self.assertEqual(len(run_root.call_args_list), 4)
        cleanup = run_root.call_args_list[3].args[0]
        self.assertEqual(cleanup[cleanup.index("--") + 1 :][-1], "/home/akadmin")

    def test_control_plane_authorities_are_boot_side_and_never_zfs_promoted(self) -> None:
        self.assertEqual(setup.BOOTSTRAP_RUNTIME_ROOT, pathlib.Path("/var/lib/nas-control-plane"))
        self.assertTrue(setup.KEEPASS_DATABASE.is_relative_to(setup.BOOTSTRAP_RUNTIME_ROOT))
        source = (SERVICES / "nas_setup.py").read_text(encoding="utf-8")
        self.assertNotIn("promote_bootstrap_runtime", source)
        self.assertNotIn("operational-runtime-select", source)

    def test_identity_database_regeneration_does_not_replace_the_new_boot_side_keepass(self) -> None:
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
                    "services": {"syncthing": "on-demand"},
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
                mock.patch.object(setup, "JOURNAL_PATH", root / "missing-journal.json"),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "validate_service_request"),
            ):
                result = setup.first_start_status(str(config))
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["serviceCount"], 1)
        self.assertNotIn("featureCount", result)

    def status_with_journal(
        self,
        journal: dict[str, object] | str | None,
        *,
        storage_verified: bool = True,
        with_config: bool = True,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = self.config_file(root) if with_config else root / "missing-first-run.json"
            journal_path = root / "first-run-journal.json"
            if isinstance(journal, str):
                journal_path.write_text(journal, encoding="utf-8")
            elif journal is not None:
                journal_path.write_text(json.dumps(journal), encoding="utf-8")
            with (
                mock.patch.object(setup, "STATE_PATH", root / "missing-state.json"),
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "storage_ready", return_value=storage_verified),
                mock.patch.object(setup, "validate_service_request"),
            ):
                return setup.first_start_status(str(config))

    @staticmethod
    def journal(status: str, step: str | None, **extra: object) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "workflow": "first-run-v2",
            "fingerprint": "f" * 64,
            "status": status,
            "currentStep": step,
            "updatedAt": 1700000000,
            "steps": {step: {"status": "failed", "error": "SECRET-BEARING STEP DETAIL"}} if step else {},
            **extra,
        }

    def test_manual_recovery_journal_is_reported_before_submission(self) -> None:
        result = self.status_with_journal(self.journal("manual-recovery-required", "identity-database-regeneration"))
        self.assertEqual(result["status"], "manual-recovery-required")
        self.assertNotIn("planDigest", result, "a blocked plan must not be confirmable")
        self.assertEqual(
            result["setupJournal"],
            {
                "schemaVersion": 1,
                "workflow": "first-run-v2",
                "status": "manual-recovery-required",
                "step": "identity-database-regeneration",
                "updatedAt": 1700000000,
            },
        )
        self.assertIn("identity-database-regeneration", str(result["message"]))
        self.assertIn("reconcile-first-run", str(result["message"]))
        self.assertNotIn("SECRET-BEARING", json.dumps(result))

    def test_verifiable_storage_recovery_stays_submittable(self) -> None:
        journal = self.journal("manual-recovery-required", "storage")
        resumable = self.status_with_journal(journal, storage_verified=True)
        self.assertEqual(resumable["status"], "ready")
        self.assertEqual(resumable["setupJournal"]["status"], "manual-recovery-required")
        blocked = self.status_with_journal(journal, storage_verified=False)
        self.assertEqual(blocked["status"], "manual-recovery-required")

    def test_storage_proof_uses_the_worker_mount_verification(self) -> None:
        summary = setup.setup_journal_summary(self.journal("manual-recovery-required", "storage"))
        for pool, dataset, mount_check, blocked in (
            (True, True, 0, False),
            (True, True, 1, True),
            (True, False, 0, True),
            (False, False, 0, True),
        ):
            with (
                self.subTest(pool=pool, dataset=dataset, mount_check=mount_check),
                mock.patch.object(setup, "pool_exists", return_value=pool),
                mock.patch.object(setup, "dataset_exists", return_value=dataset),
                mock.patch.object(
                    setup,
                    "run_storage_host",
                    return_value=setup.Completed(("nas-zfs-mount-check",), "", "", mount_check),
                ) as mount,
            ):
                self.assertEqual(setup.setup_journal_blocker(summary) is not None, blocked)
                if pool and dataset:
                    mount.assert_called_once_with(
                        ["nas-zfs-mount-check"], check=False, timeout_seconds=setup.STATUS_STORAGE_PROBE_SECONDS
                    )

    def test_storage_proof_stays_within_the_status_deadline(self) -> None:
        summary = setup.setup_journal_summary(self.journal("manual-recovery-required", "storage"))
        hung = subprocess.TimeoutExpired(["zpool", "list"], setup.STATUS_STORAGE_PROBE_SECONDS)
        with mock.patch.object(setup.subprocess, "run", side_effect=hung) as listing:
            self.assertIsNotNone(setup.setup_journal_blocker(summary))
        self.assertEqual(listing.call_args.kwargs["timeout"], setup.STATUS_STORAGE_PROBE_SECONDS)
        with (
            mock.patch.object(setup, "pool_exists", return_value=True),
            mock.patch.object(setup, "dataset_exists", return_value=True),
            mock.patch.object(setup, "run_root", side_effect=setup.SetupError("Command timed out")) as run_root,
        ):
            self.assertIsNotNone(setup.setup_journal_blocker(summary))
        command = run_root.call_args.args[0]
        self.assertIn(f"--property=RuntimeMaxSec={setup.STATUS_STORAGE_PROBE_SECONDS}", command[: command.index("--")])
        self.assertEqual(run_root.call_args.kwargs["timeout_seconds"], setup.STATUS_STORAGE_PROBE_SECONDS)

    def test_full_status_path_with_slow_storage_proof_fits_the_api_deadline(self) -> None:
        budgets: list[float] = []

        def listing(command, **kwargs):
            budgets.append(kwargs["timeout"])
            return subprocess.CompletedProcess(command, 0)

        def mount_check(command, **kwargs):
            budgets.append(kwargs["timeout_seconds"])
            return setup.Completed(tuple(command), "", "", 0)

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = self.config_file(root)
            journal_path = root / "journal.json"
            journal_path.write_text(json.dumps(self.journal("manual-recovery-required", "storage")), encoding="utf-8")
            with (
                mock.patch.object(setup, "STATE_PATH", root / "missing-state.json"),
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
                mock.patch.object(setup.subprocess, "run", side_effect=listing),
                mock.patch.object(setup, "run_root", side_effect=mount_check),
                mock.patch.object(setup, "validate_service_request"),
            ):
                result = setup.first_start_status(str(config))
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["storage"]["poolPresent"])
        # zpool list, zfs list and the mount check, each bounded; no unbounded re-probe.
        self.assertEqual(len(budgets), 3)
        self.assertLess(sum(budgets), 60)

    def test_interrupted_and_acknowledged_journals_remain_resumable(self) -> None:
        for status in ("failed", "reconciled", "running"):
            with self.subTest(status=status):
                result = self.status_with_journal(self.journal(status, "identity-accounts"))
                self.assertEqual(result["status"], "ready")
                self.assertEqual(result["setupJournal"]["status"], status)
                self.assertEqual(result["setupJournal"]["step"], "identity-accounts")
        for journal in (None, self.journal("complete", None), self.journal("cancelled", None)):
            with self.subTest(journal=journal):
                result = self.status_with_journal(journal)
                self.assertEqual(result["status"], "ready")
                self.assertIsNone(result["setupJournal"])

    def test_non_root_administrator_reads_the_root_only_journal_through_sudo(self) -> None:
        journal = self.journal("manual-recovery-required", "identity-accounts")
        denied = setup.JournalError("Invalid operation journal")
        denied.__cause__ = PermissionError(13, "Permission denied")

        def load(path: pathlib.Path) -> None:
            if path == setup.JOURNAL_PATH:
                raise denied

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = self.config_file(root)
            common = (
                mock.patch.object(setup, "STATE_PATH", root / "missing-state.json"),
                mock.patch.object(setup, "load_json", side_effect=load),
                mock.patch.object(setup.os, "geteuid", return_value=1000),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "validate_service_request"),
            )
            escalated = setup.Completed(("sudo",), json.dumps(journal), "", 0)
            with contextlib.ExitStack() as stack:
                for patch in common:
                    stack.enter_context(patch)
                privileged = stack.enter_context(
                    mock.patch.object(setup, "run_root_noninteractive", return_value=escalated)
                )
                result = setup.first_start_status(str(config))
            privileged.assert_called_once_with(
                ["cat", "--", str(setup.JOURNAL_PATH)], check=False, timeout_seconds=setup.STATUS_STORAGE_PROBE_SECONDS
            )
            self.assertEqual(result["status"], "manual-recovery-required")
            self.assertEqual(result["setupJournal"]["step"], "identity-accounts")

            refused = setup.Completed(("sudo",), "", "sudo: a password is required", 1)
            with contextlib.ExitStack() as stack:
                for patch in common:
                    stack.enter_context(patch)
                stack.enter_context(mock.patch.object(setup, "run_root_noninteractive", return_value=refused))
                unreadable = setup.first_start_status(str(config))
            with contextlib.ExitStack() as stack:
                for patch in common:
                    stack.enter_context(patch)
                stack.enter_context(
                    mock.patch.object(
                        setup,
                        "run_root_noninteractive",
                        side_effect=setup.SetupError("Command timed out after 12 seconds"),
                    )
                )
                stalled = setup.first_start_status(str(config))
        self.assertEqual(unreadable["status"], "journal-unreadable")
        self.assertIn("a password is required", unreadable["message"])
        self.assertNotIn("planDigest", unreadable)
        self.assertEqual(stalled["status"], "journal-unreadable")
        self.assertIn("timed out", stalled["message"])

    def test_sudo_start_failure_reports_an_unreadable_journal(self) -> None:
        denied = setup.JournalError("Invalid operation journal")
        denied.__cause__ = PermissionError(13, "Permission denied")
        with (
            mock.patch.object(setup, "load_json", side_effect=denied),
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(
                setup, "run_root_noninteractive", side_effect=FileNotFoundError(2, "No such file", "sudo")
            ),
            self.assertRaisesRegex(setup.JournalUnreadableError, "No such file"),
        ):
            setup.load_setup_journal()

    def test_bounded_privileged_commands_bound_the_sudo_refresh(self) -> None:
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

        def record(command, **kwargs):
            calls.append((tuple(command), kwargs))
            return setup.Completed(tuple(command), "", "", 0)

        with (
            mock.patch.object(setup.os, "geteuid", return_value=1000),
            mock.patch.object(setup, "run", side_effect=record),
        ):
            setup.run_root(["nas-zfs-mount-check"], check=False, timeout_seconds=12)
            setup.run_root(["systemctl", "start", "unit"])
        self.assertEqual(calls[0], (("sudo", "-n", "-v"), {"check": False, "timeout_seconds": 12}))
        self.assertEqual(calls[1][1]["timeout_seconds"], 12)
        self.assertEqual(calls[2], (("sudo", "-n", "-v"), {"check": False}))

    def test_recovery_outranks_a_missing_plan(self) -> None:
        result = self.status_with_journal(
            self.journal("manual-recovery-required", "identity-accounts"), with_config=False
        )
        self.assertEqual(result["status"], "manual-recovery-required")
        self.assertEqual(self.status_with_journal("{not json", with_config=False)["status"], "journal-invalid")
        self.assertEqual(self.status_with_journal(None, with_config=False)["status"], "configuration-missing")

    def test_unusable_journal_blocks_submission(self) -> None:
        invalid = self.status_with_journal("{not json")
        self.assertEqual(invalid["status"], "journal-invalid")
        self.assertNotIn("planDigest", invalid)
        for journal in (
            self.journal("running", "storage", workflow="identity-accounts"),
            self.journal("failed", "storage", schemaVersion=2),
            self.journal("corrupted", "storage"),
            {key: value for key, value in self.journal("failed", "storage").items() if key != "status"},
        ):
            with self.subTest(journal=journal):
                self.assertEqual(self.status_with_journal(journal)["status"], "manual-recovery-required")

    def test_failed_job_document_reports_a_blocking_journal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            journal_path = pathlib.Path(tmp) / "journal.json"
            journal_path.write_text(
                json.dumps(self.journal("manual-recovery-required", "bootstrap-authority-retirement")),
                encoding="utf-8",
            )
            with (
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
                mock.patch.object(setup, "storage_ready", side_effect=AssertionError("storage probe not needed")),
            ):
                blocked = setup.first_start_job_recovery()
            journal_path.write_text(json.dumps(self.journal("failed", "identity-accounts")), encoding="utf-8")
            with mock.patch.object(setup, "JOURNAL_PATH", journal_path):
                retryable = setup.first_start_job_recovery()
        self.assertIs(blocked["manualRecovery"]["required"], True)
        self.assertIn("bootstrap-authority-retirement", blocked["manualRecovery"]["message"])
        self.assertNotIn("manualRecovery", retryable)
        self.assertEqual(retryable["setupJournal"]["status"], "failed")

    def test_acknowledgement_republishes_first_start_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = self.config_file(root)
            journal_path = root / "journal.json"
            journal_path.write_text(
                json.dumps(
                    self.journal("manual-recovery-required", "identity-accounts", metadata={"configPath": str(config)})
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(setup, "STATE_PATH", root / "missing-state.json"),
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
                mock.patch.object(setup, "pool_exists", return_value=True),
                mock.patch.object(setup, "validate_service_request"),
                mock.patch.object(setup, "publish_first_start_status") as publish,
            ):
                self.assertEqual(setup.first_start_status(str(config))["status"], "manual-recovery-required")
                result = setup.reconcile_first_run("repaired the Authentik database from the console")
            published = publish.call_args.args[0]
        self.assertEqual(result["status"], "reconciled")
        self.assertEqual(result["firstStartStatus"], "ready")
        self.assertEqual(published["status"], "ready")
        self.assertEqual(published["setupJournal"]["status"], "reconciled")

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

    def test_existing_keepass_database_is_replaced_after_directory_ownership_setup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = pathlib.Path(tmp) / "secrets" / "NAS.kdbx"
            database.parent.mkdir()
            database.write_text("fixture", encoding="utf-8")

            def root(command, **_kwargs):
                if command[:2] == ["rm", "--"]:
                    database.unlink()
                return setup.Completed(tuple(command), "", "")

            def admin(command, **_kwargs):
                if "db-create" in command:
                    database.write_text("fresh", encoding="utf-8")
                return setup.Completed(tuple(command), "", "")

            with (
                mock.patch.object(setup, "KEEPASS_DATABASE", database),
                mock.patch.object(setup, "run_root", side_effect=root) as run_root,
                mock.patch.object(setup, "run_admin", side_effect=admin) as run_admin,
            ):
                self.assertEqual(setup.verify_or_create_database("password", True), "created")
        self.assertEqual(run_root.call_args_list[0].args[0][0], "install")
        self.assertEqual(run_root.call_args_list[1].args[0][:2], ["rm", "--"])
        self.assertIn("db-create", run_admin.call_args_list[0].args[0])
        self.assertIn("db-info", run_admin.call_args_list[1].args[0])


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
