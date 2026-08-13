from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
import urllib.error
from email.message import Message
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES))
SPEC = importlib.util.spec_from_file_location("nas_identity_sync", SERVICES / "nas_identity_sync.py")
assert SPEC and SPEC.loader
sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sync
SPEC.loader.exec_module(sync)
FIXTURE = ROOT / "tests" / "fixtures" / "authentik-identity.json"


class IdentitySyncTests(unittest.TestCase):
    def setUp(self):
        self._journal_tmp = tempfile.TemporaryDirectory()
        self._journal_patches = [
            mock.patch.object(
                sync,
                "ACCOUNT_JOURNAL_PATH",
                pathlib.Path(self._journal_tmp.name) / "account-plan-journal.json",
            ),
            mock.patch.object(
                sync,
                "SYNCTHING_JOURNAL_PATH",
                pathlib.Path(self._journal_tmp.name) / "syncthing-reconcile-journal.json",
            ),
        ]
        for patch in self._journal_patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self._journal_patches):
            patch.stop()
        self._journal_tmp.cleanup()

    def model(self):
        return sync.fixture_model(FIXTURE)

    def test_model_contains_identity_only_and_default_administrator(self):
        model = self.model()
        self.assertEqual([user.uid for user in model.users], ["admin", "alice", "guest"])
        self.assertEqual(model.administrators, ("admin",))
        self.assertFalse(hasattr(model, "volumes"))

    def test_copyparty_share_attributes_have_no_effect(self):
        data = json.loads(FIXTURE.read_text())
        media = next(group for group in data["groups"] if group["name"] == "share-media")
        media["attributes"] = {
            "nasShareName": "should-not-exist",
            "nasSharePath": "../unsafe",
            "nasShareFlags": ["anything"],
        }
        model = sync.build_model(data)
        self.assertIn("share-media", {group.name for group in model.groups})
        self.assertFalse(hasattr(model, "volumes"))

    def test_disabled_authentik_user_is_removed(self):
        self.assertNotIn("disabled", {user.uid for user in self.model().users})

    def test_capability_report_uses_shared_groups(self):
        report = sync.capability_status(self.model())
        users = {entry["id"]: entry for entry in report["users"]}
        self.assertTrue(users["admin"]["capabilities"]["ai"]["allowed"])
        self.assertTrue(users["alice"]["capabilities"]["vault"]["allowed"])
        self.assertFalse(users["guest"]["capabilities"]["ai"]["allowed"])
        self.assertEqual(report["managementUrl"], "/identity/if/user/")

    def test_syncthing_devices_are_derived_only_from_authentik_attributes(self):
        folders, devices = sync.desired_syncthing(self.model())
        self.assertEqual(set(folders), {"nas-admin-backup", "nas-alice-backup"})
        self.assertEqual(len(devices), 2)
        self.assertTrue(all(folder["type"] == "receiveonly" for folder in folders.values()))

    def test_empty_authentik_attribute_removes_managed_folder(self):
        model = self.model()
        alice = next(user for user in model.users if user.uid == "alice")
        users = tuple(
            sync.User(user.uid, user.email, user.display_name, user.groups, {**user.attrs, "nasSyncthingDevices": []})
            if user.uid == alice.uid
            else user
            for user in model.users
        )
        folders, _ = sync.desired_syncthing(sync.IdentityModel(users, model.groups, model.administrators))
        self.assertNotIn("nas-alice-backup", folders)

    def test_at_least_one_explicit_nas_admin_is_required(self):
        data = json.loads(FIXTURE.read_text())
        data["users"][0]["groups_obj"] = [
            group for group in data["users"][0]["groups_obj"] if group["name"] != "nas_admin"
        ]
        admin_group = next(group for group in data["groups"] if group["name"] == "nas_admin")
        admin_group["users_obj"] = []
        data["users"][0]["is_superuser"] = True
        with self.assertRaisesRegex(sync.SyncError, "explicitly to the nas_admin group"):
            sync.build_model(data)

    def test_group_side_membership_survives_missing_user_group_expansion(self):
        data = json.loads(FIXTURE.read_text())
        data["users"][0]["groups_obj"] = []
        model = sync.build_model(data)
        self.assertEqual(model.administrators, ("admin",))
        admin = next(user for user in model.users if user.uid == "admin")
        self.assertIn("nas_admin", admin.groups)

    def test_membership_expansions_resolve_primary_key_only_objects(self):
        data = json.loads(FIXTURE.read_text())
        admin_pk = data["users"][0]["pk"]
        admin_group_pk = data["groups"][0]["pk"]
        data["users"][0]["groups_obj"] = [{"pk": admin_group_pk}]
        data["groups"][0]["users_obj"] = [{"pk": admin_pk}]
        model = sync.build_model(data)
        self.assertEqual(model.administrators, ("admin",))
        admin = next(user for user in model.users if user.uid == "admin")
        self.assertIn(sync.ADMIN_GROUP, admin.groups)

    def test_multiple_enabled_nas_admins_are_allowed(self):
        data = json.loads(FIXTURE.read_text())
        data["users"][1]["groups_obj"].append({"pk": "g-admin", "name": "nas_admin"})
        model = sync.build_model(data)
        self.assertEqual(model.administrators, ("admin", "alice"))

    def test_conflicting_device_definitions_are_rejected(self):
        model = self.model()
        users = list(model.users)
        first = users[0]
        second = users[1]
        raw = json.loads(first.attrs["nasSyncthingDevice"][0])
        raw["name"] = "Different name"
        users[1] = sync.User(
            second.uid, second.email, second.display_name, second.groups, {"nasSyncthingDevices": [json.dumps([raw])]}
        )
        with self.assertRaisesRegex(sync.SyncError, "conflicting Authentik definitions"):
            sync.desired_syncthing(sync.IdentityModel(tuple(users), model.groups, model.administrators))

    def test_authentik_api_pagination_is_bounded(self):
        pages = [
            {"results": [{"pk": 1}], "pagination": {"next": 2}},
            {"results": [{"pk": 2}], "pagination": {"next": 0}},
        ]
        with mock.patch.object(sync, "authentik_request", side_effect=pages) as request:
            values = sync.authentik_list("token", "core/groups/")
        self.assertEqual([value["pk"] for value in values], [1, 2])
        self.assertEqual(request.call_count, 2)

    def test_bootstrap_and_runtime_tokens_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "api-token"
            bootstrap = pathlib.Path(tmp) / "bootstrap-token"
            runtime.write_text("runtime-scoped-token")
            bootstrap.write_text("bootstrap-privileged-token")
            with (
                mock.patch.object(sync, "AUTHENTIK_TOKEN_FILE", runtime),
                mock.patch.object(sync, "AUTHENTIK_BOOTSTRAP_TOKEN_FILE", bootstrap),
            ):
                self.assertEqual(sync.authentik_token(), "runtime-scoped-token")
                self.assertEqual(sync.authentik_token(bootstrap=True), "bootstrap-privileged-token")

    def test_bootstrap_uses_superuser_only_for_nas_admin(self):
        existing = [
            {"pk": "admin", "name": sync.ADMIN_GROUP, "is_superuser": False},
            {"pk": "users", "name": sync.USER_GROUP, "is_superuser": True},
        ]
        refreshed = [
            {"pk": "admin", "name": sync.ADMIN_GROUP, "is_superuser": True, "users_obj": [{"username": "admin"}]},
            {"pk": "users", "name": sync.USER_GROUP, "is_superuser": False},
        ]
        calls = []
        with (
            mock.patch.object(sync, "authentik_list", side_effect=[existing, refreshed]),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=lambda *args, **kwargs: calls.append((args, kwargs)) or {},
            ),
        ):
            result = sync.ensure_groups("bootstrap-token")
        patched = {args[1]: kwargs["body"]["is_superuser"] for args, kwargs in calls if kwargs.get("method") == "PATCH"}
        self.assertTrue(patched["core/groups/admin/"])
        self.assertFalse(patched["core/groups/users/"])
        self.assertEqual(set(result["correctedSuperuserGroups"]), {sync.ADMIN_GROUP, sync.USER_GROUP})
        self.assertIsNone(result["bootstrappedAdministrator"])

    def test_bootstrap_adds_akadmin_when_admin_group_is_empty(self):
        groups = [{"pk": "admin-uuid", "name": sync.ADMIN_GROUP, "is_superuser": True}]
        refreshed = [{"pk": "admin-uuid", "name": sync.ADMIN_GROUP, "is_superuser": True, "users_obj": []}]
        users = [{"pk": 1, "username": "akadmin", "is_active": True}]
        calls = []
        with (
            mock.patch.object(sync, "authentik_list", side_effect=[groups, refreshed, users]),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=lambda *args, **kwargs: calls.append((args, kwargs)) or {},
            ),
        ):
            result = sync.ensure_groups("bootstrap-token")
        self.assertEqual(result["bootstrappedAdministrator"], "akadmin")
        self.assertIn(
            (("bootstrap-token", "core/groups/admin-uuid/add_user/"), {"method": "POST", "body": {"pk": 1}}),
            calls,
        )

    def test_verify_token_does_not_mutate_identity_state(self):
        with (
            mock.patch.object(
                sync, "authentik_list", side_effect=[[], [{"name": name} for name in sync.RESERVED_GROUPS]]
            ) as listing,
            mock.patch.object(sync, "authentik_request") as write,
        ):
            result = sync.verify_token("scoped")
        self.assertTrue(result["ok"])
        self.assertEqual(listing.call_count, 2)
        write.assert_not_called()

    def test_bootstrap_runtime_token_creates_service_account_role_binding_and_token(self):
        calls = []

        def listing(token, path):
            if path.startswith("core/users/"):
                return []
            if path.startswith("rbac/roles/"):
                return [{"pk": "role-pk", "name": sync.AUTOMATION_ROLE}]
            if path.startswith("core/tokens/"):
                return []
            raise AssertionError(path)

        def request(token, path, **kwargs):
            calls.append((path, kwargs))
            if path == "core/users/service_account/":
                return {"user_pk": 42}
            return {}

        with (
            mock.patch.object(sync, "authentik_list", side_effect=listing),
            mock.patch.object(sync, "authentik_request", side_effect=request),
            mock.patch.object(sync.secrets, "token_urlsafe", return_value="scoped-runtime-token-value"),
        ):
            result = sync.provision_runtime_token("bootstrap")

        self.assertEqual(result["token"], "scoped-runtime-token-value")
        self.assertIn(("rbac/roles/role-pk/add_user/", {"method": "POST", "body": {"pk": 42}}), calls)
        self.assertTrue(any(path == "core/tokens/" for path, _ in calls))
        self.assertIn(
            (
                f"core/tokens/{sync.AUTOMATION_TOKEN_IDENTIFIER}/set_key/",
                {"method": "POST", "body": {"key": "scoped-runtime-token-value"}},
            ),
            calls,
        )

    def test_bootstrap_runtime_token_requires_deployed_role(self):
        with (
            mock.patch.dict(sync.os.environ, {"NAS_AUTOMATION_ROLE_WAIT_SECONDS": "0"}),
            mock.patch.object(
                sync,
                "authentik_list",
                side_effect=[
                    [{"pk": 42, "username": sync.AUTOMATION_USER}],
                    [],
                ],
            ),
        ):
            with self.assertRaisesRegex(sync.SyncError, "automation role is missing"):
                sync.provision_runtime_token("bootstrap")

    def test_bootstrap_runtime_token_waits_for_async_blueprint_role(self):
        roles = [[], [{"pk": "role-pk", "name": sync.AUTOMATION_ROLE}]]
        with (
            mock.patch.dict(sync.os.environ, {"NAS_AUTOMATION_ROLE_WAIT_SECONDS": "1"}),
            mock.patch.object(
                sync,
                "authentik_list",
                side_effect=lambda _token, path: (
                    [{"pk": 42, "username": sync.AUTOMATION_USER}]
                    if path.startswith("core/users/")
                    else roles.pop(0)
                    if path.startswith("rbac/roles/")
                    else []
                ),
            ),
            mock.patch.object(sync, "authentik_request", return_value={}),
            mock.patch.object(sync, "_retry_delay", return_value=0.01),
            mock.patch.object(sync.time, "sleep"),
            mock.patch.object(sync.secrets, "token_urlsafe", return_value="scoped-runtime-token-value"),
        ):
            result = sync.provision_runtime_token("bootstrap")
        self.assertEqual(result["role"], sync.AUTOMATION_ROLE)

    def test_disabled_syncthing_returns_reconciliation_shape(self):
        with mock.patch.object(sync, "SYNCTHING_ENABLED", False):
            result = sync.reconcile_syncthing(self.model())
        self.assertEqual(
            result,
            {
                "folders": 0,
                "devices": 0,
                "removedFolders": 0,
                "removedDevices": 0,
            },
        )

    def test_reconciliation_uses_only_reserved_object_endpoints(self):
        calls = []
        folders, devices = sync.desired_syncthing(self.model())

        def request(path, **kwargs):
            calls.append((path, kwargs))
            if path == "/rest/config/folders":
                return list(folders.values())
            if path == "/rest/config/devices":
                return list(devices.values())
            if path.endswith("restart-required"):
                return {"requiresRestart": False}
            return {}

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(sync, "SYNCTHING_ENABLED", True),
            mock.patch.object(sync, "STATE_PATH", pathlib.Path(tmp) / "state.json"),
            mock.patch.object(sync, "syncthing_request", side_effect=request),
            mock.patch.object(sync, "ensure_syncthing_folder"),
        ):
            result = sync.reconcile_syncthing(self.model())
        self.assertEqual(result["folders"], 2)
        paths = [path for path, _ in calls]
        self.assertTrue(any(path.startswith("/rest/config/folders/nas-") for path in paths))
        self.assertFalse(any(path == "/rest/config" for path in paths))

    def test_syncthing_state_commits_only_after_observed_configuration_matches(self):
        folders, devices = sync.desired_syncthing(self.model())
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "state.json"
            journal_path = pathlib.Path(tmp) / "journal.json"

            def request(path, **kwargs):
                if path == "/rest/config/folders":
                    return list(folders.values())
                if path == "/rest/config/devices":
                    return list(devices.values())
                if path.endswith("restart-required"):
                    return {"requiresRestart": False}
                return {}

            with (
                mock.patch.object(sync, "SYNCTHING_ENABLED", True),
                mock.patch.object(sync, "STATE_PATH", state_path),
                mock.patch.object(sync, "SYNCTHING_JOURNAL_PATH", journal_path),
                mock.patch.object(sync, "syncthing_request", side_effect=request),
                mock.patch.object(sync, "ensure_syncthing_folder"),
            ):
                sync.reconcile_syncthing(self.model())

            state = json.loads(state_path.read_text())
            self.assertEqual(state["schemaVersion"], 2)
            self.assertEqual(state["generation"], sync.syncthing_generation(folders, devices))
            self.assertFalse(journal_path.exists())

    def test_syncthing_observation_failure_keeps_journal_and_old_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = pathlib.Path(tmp) / "state.json"
            state_path.write_text('{"folders":["old"],"devices":[]}\n')
            journal_path = pathlib.Path(tmp) / "journal.json"

            def request(path, **kwargs):
                if path in {"/rest/config/folders", "/rest/config/devices"}:
                    return []
                return {}

            with (
                mock.patch.object(sync, "SYNCTHING_ENABLED", True),
                mock.patch.object(sync, "STATE_PATH", state_path),
                mock.patch.object(sync, "SYNCTHING_JOURNAL_PATH", journal_path),
                mock.patch.object(sync, "syncthing_request", side_effect=request),
                mock.patch.object(sync, "ensure_syncthing_folder"),
            ):
                with self.assertRaisesRegex(sync.SyncError, "did not converge"):
                    sync.reconcile_syncthing(self.model())

            self.assertEqual(json.loads(state_path.read_text())["folders"], ["old"])
            self.assertEqual(json.loads(journal_path.read_text())["phase"], "mutated")

    def test_folder_creation_requires_copyparty_parent_and_sets_leaf_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = root / "users" / "alice" / "syncthing"
            path.parent.mkdir(parents=True)
            user = mock.Mock(pw_uid=os.getuid())
            group = mock.Mock(gr_gid=os.getgid())
            with (
                mock.patch.object(sync, "SHARE_ROOT", root),
                mock.patch.object(sync.pwd, "getpwnam", return_value=user),
                mock.patch.object(sync.grp, "getgrnam", return_value=group),
            ):
                sync.ensure_syncthing_folder(path)
            self.assertTrue(path.is_dir())
            self.assertEqual(path.stat().st_mode & 0o7777, 0o2770)

    def test_folder_creation_does_not_create_missing_personal_share(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = root / "users" / "alice" / "syncthing"
            with (
                mock.patch.object(sync, "SHARE_ROOT", root),
                self.assertRaisesRegex(sync.SyncError, "personal-share directory does not exist"),
            ):
                sync.ensure_syncthing_folder(path)

    def test_folder_creation_rejects_user_controlled_parent_symlink(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as target_tmp:
            root = pathlib.Path(tmp)
            (root / "users").mkdir()
            (root / "users" / "alice").symlink_to(target_tmp, target_is_directory=True)
            path = root / "users" / "alice" / "syncthing"
            with mock.patch.object(sync, "SHARE_ROOT", root), self.assertRaisesRegex(sync.SyncError, "unsafe"):
                sync.ensure_syncthing_folder(path)
            self.assertFalse((pathlib.Path(target_tmp) / "syncthing").exists())

    def test_apply_account_plan_creates_user_sets_password_and_marks_management(self):
        groups = [{"pk": f"pk-{name}", "name": name} for name in sync.RESERVED_GROUPS]
        next(group for group in groups if group["name"] == sync.ADMIN_GROUP)["users"] = [1]
        users = [{"pk": 1, "username": "akadmin", "is_active": True, "groups": [f"pk-{sync.ADMIN_GROUP}"]}]
        calls = []

        def request(token, path, **kwargs):
            calls.append((token, path, kwargs))
            if path == "core/users/" and kwargs.get("method") == "POST":
                return {"pk": 42, "username": "alice"}
            return {}

        plan = {
            "schemaVersion": 1,
            "accounts": [
                {
                    "username": "alice",
                    "name": "Alice",
                    "email": "alice@nas.local",
                    "active": True,
                    "groups": [sync.USER_GROUP, "nas_allow_files"],
                    "attributes": {"department": "home"},
                    "password": "temporary-secret",
                }
            ],
        }
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(sync, "authentik_request", side_effect=request),
        ):
            result = sync.apply_account_plan("bootstrap", plan)

        self.assertEqual(result["created"], ["alice"])
        self.assertEqual(result["passwordsChanged"], ["alice"])
        create = next(item for item in calls if item[1] == "core/users/")
        self.assertEqual(create[2]["body"]["type"], "internal")
        self.assertTrue(create[2]["body"]["attributes"]["nasManagedBySetup"])
        self.assertNotIn("temporary-secret", json.dumps(result))
        password = next(item for item in calls if item[1] == "core/users/42/set_password/")
        self.assertEqual(password[2]["body"], {"password": "temporary-secret"})

    def test_apply_account_plan_preserves_non_reserved_groups(self):
        groups = [{"pk": f"pk-{name}", "name": name} for name in sync.RESERVED_GROUPS] + [
            {"pk": "custom-pk", "name": "family"}
        ]
        next(group for group in groups if group["name"] == sync.ADMIN_GROUP)["users"] = [1]
        users = [
            {"pk": 1, "username": "akadmin", "is_active": True, "groups": [f"pk-{sync.ADMIN_GROUP}"], "attributes": {}},
            {
                "pk": 7,
                "username": "alice",
                "name": "Old",
                "email": "old@nas.local",
                "is_active": True,
                "groups": ["custom-pk", f"pk-{sync.USER_GROUP}", "pk-nas_allow_ai"],
                "attributes": {"existing": "kept", "nasManagedBySetup": True},
            },
        ]
        calls = []
        plan = {
            "schemaVersion": 1,
            "accounts": [
                {
                    "username": "alice",
                    "name": "Alice",
                    "email": "alice@nas.local",
                    "active": True,
                    "groups": [sync.USER_GROUP, "nas_allow_files"],
                    "attributes": {"new": "value"},
                }
            ],
        }
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=lambda *args, **kwargs: calls.append((args, kwargs)) or {},
            ),
        ):
            result = sync.apply_account_plan("bootstrap", plan)

        self.assertEqual(result["updated"], ["alice"])
        patch = next(item for item in calls if item[0][1] == "core/users/7/")
        body = patch[1]["body"]
        self.assertIn("custom-pk", body["groups"])
        self.assertIn("pk-nas_allow_files", body["groups"])
        self.assertNotIn("pk-nas_allow_ai", body["groups"])
        self.assertEqual(body["attributes"]["existing"], "kept")
        self.assertEqual(body["attributes"]["new"], "value")

    def test_deactivate_missing_only_affects_setup_managed_accounts(self):
        groups = [{"pk": f"pk-{name}", "name": name} for name in sync.RESERVED_GROUPS]
        next(group for group in groups if group["name"] == sync.ADMIN_GROUP)["users"] = [1]
        users = [
            {"pk": 1, "username": "akadmin", "is_active": True, "groups": [f"pk-{sync.ADMIN_GROUP}"], "attributes": {}},
            {
                "pk": 8,
                "username": "old-managed",
                "groups": [f"pk-{sync.USER_GROUP}"],
                "attributes": {"nasManagedBySetup": True},
            },
            {
                "pk": 9,
                "username": "manual",
                "groups": [f"pk-{sync.USER_GROUP}"],
                "attributes": {},
            },
        ]
        calls = []
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=lambda *args, **kwargs: calls.append((args, kwargs)) or {},
            ),
        ):
            result = sync.apply_account_plan(
                "bootstrap",
                {"schemaVersion": 1, "accounts": [], "deactivateMissingManagedAccounts": True},
            )
        self.assertEqual(result["deactivated"], ["old-managed"])
        self.assertEqual([item[0][1] for item in calls], ["core/users/8/"])
        self.assertIn("pk-nas_disabled", calls[0][1]["body"]["groups"])

    def test_inactive_account_plan_drops_active_reserved_groups(self):
        account = sync.normalized_account_plan(
            {
                "username": "alice",
                "active": False,
                "groups": [sync.USER_GROUP, "nas_allow_files"],
            },
            0,
        )
        self.assertEqual(account["groups"], [sync.DISABLED_GROUP])

    def test_account_plan_rejects_unknown_fields_and_non_boolean_deactivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan_path = pathlib.Path(tmp) / "plan.json"
            plan_path.write_text(json.dumps({"accounts": [], "deactivateMissingManagedAccount": True}))
            with self.assertRaisesRegex(sync.SyncError, "unknown field"):
                sync.load_account_plan(str(plan_path))

            plan_path.write_text(json.dumps({"accounts": [], "deactivateMissingManagedAccounts": "false"}))
            with self.assertRaisesRegex(sync.SyncError, "must be true or false"):
                sync.load_account_plan(str(plan_path))

        with self.assertRaisesRegex(sync.SyncError, "unknown field"):
            sync.normalized_account_plan({"username": "alice", "emali": "typo"}, 0)

    def test_account_plan_cannot_remove_last_enabled_administrator(self):
        groups = [{"pk": f"pk-{name}", "name": name} for name in sync.RESERVED_GROUPS]
        next(group for group in groups if group["name"] == sync.ADMIN_GROUP)["users"] = [7]
        users = [
            {
                "pk": 7,
                "username": "operator",
                "is_active": True,
                "groups": [f"pk-{sync.ADMIN_GROUP}"],
                "attributes": {"nasManagedBySetup": True},
            }
        ]
        plan = {"accounts": [{"username": "operator", "active": True, "groups": [sync.USER_GROUP]}]}
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(sync, "authentik_request") as request,
        ):
            with self.assertRaisesRegex(sync.SyncError, "no enabled members"):
                sync.apply_account_plan("bootstrap", plan)
        request.assert_not_called()

    def test_account_plan_can_replace_the_only_administrator_atomically(self):
        groups = [{"pk": f"pk-{name}", "name": name} for name in sync.RESERVED_GROUPS]
        next(group for group in groups if group["name"] == sync.ADMIN_GROUP)["users"] = [7]
        users = [
            {
                "pk": 7,
                "username": "old-admin",
                "is_active": True,
                "groups": [f"pk-{sync.ADMIN_GROUP}"],
                "attributes": {"nasManagedBySetup": True},
            }
        ]
        plan = {
            "accounts": [
                {"username": "old-admin", "active": True, "groups": [sync.USER_GROUP]},
                {"username": "new-admin", "active": True, "groups": [sync.ADMIN_GROUP]},
            ]
        }

        writes = []

        def request(token, path, **kwargs):
            writes.append((path, kwargs.get("method")))
            if path == "core/users/" and kwargs.get("method") == "POST":
                return {"pk": 8, "username": "new-admin"}
            return {}

        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(sync, "authentik_request", side_effect=request),
        ):
            result = sync.apply_account_plan("bootstrap", plan)
        self.assertEqual(result["administrators"], ["new-admin"])
        self.assertEqual(
            writes,
            [
                ("core/users/", "POST"),
                ("core/users/7/", "PATCH"),
            ],
        )

    def test_export_account_never_returns_password(self):
        groups = [
            {"pk": "user-group", "name": sync.USER_GROUP},
            {"pk": "files-group", "name": "nas_allow_files"},
        ]
        users = [
            {
                "pk": 2,
                "username": "alice",
                "name": "Alice",
                "email": "alice@nas.local",
                "is_active": True,
                "groups": ["user-group", "files-group"],
                "attributes": {"nasManagedBySetup": True},
            }
        ]
        with mock.patch.object(sync, "authentik_list", side_effect=[users, groups]):
            exported = sync.export_account("runtime", "alice")
        self.assertEqual(exported["groups"], ["nas_allow_files", sync.USER_GROUP])
        self.assertNotIn("password", exported)

    def test_account_plan_resumes_completed_user_after_password_failure(self):
        groups = [{"pk": f"pk-{name}", "name": name} for name in sync.RESERVED_GROUPS]
        next(group for group in groups if group["name"] == sync.ADMIN_GROUP)["users"] = [1]
        initial_users = [{"pk": 1, "username": "akadmin", "is_active": True, "groups": [f"pk-{sync.ADMIN_GROUP}"]}]
        resumed_users = initial_users + [
            {
                "pk": 42,
                "username": "alice",
                "is_active": True,
                "groups": [f"pk-{sync.USER_GROUP}"],
                "attributes": {"nasManagedBySetup": True},
            }
        ]
        plan = {
            "schemaVersion": 1,
            "accounts": [
                {
                    "username": "alice",
                    "groups": [sync.USER_GROUP],
                    "password": "secret",
                }
            ],
        }
        first_calls = []

        def first_request(token, path, **kwargs):
            first_calls.append(path)
            if path == "core/users/":
                return {"pk": 42, "username": "alice"}
            if path.endswith("/set_password/"):
                raise sync.SyncError("password endpoint failed")
            return {}

        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, initial_users]),
            mock.patch.object(sync, "authentik_request", side_effect=first_request),
        ):
            with self.assertRaisesRegex(sync.SyncError, "password endpoint failed"):
                sync.apply_account_plan("runtime", plan)

        with self.assertRaisesRegex(sync.SyncError, "confirm-password-reapply"):
            sync.apply_account_plan("runtime", plan)

        second_calls = []
        with (
            mock.patch.object(sync, "ensure_groups") as groups_again,
            mock.patch.object(sync, "authentik_list", side_effect=[groups, resumed_users]),
            mock.patch.object(
                sync,
                "authentik_request",
                side_effect=lambda token, path, **kwargs: second_calls.append(path) or {},
            ),
        ):
            result = sync.apply_account_plan(
                "runtime",
                plan,
                confirm_password_reapply=True,
            )

        groups_again.assert_not_called()
        self.assertNotIn("core/users/", second_calls)
        self.assertNotIn("core/users/42/", second_calls)
        self.assertIn("core/users/42/set_password/", second_calls)
        self.assertEqual(result["created"], ["alice"])

    def test_account_plan_preview_is_password_free_and_read_only(self):
        plan = {
            "accounts": [
                {"username": "alice", "groups": [sync.USER_GROUP], "password": "secret"},
                {"username": "bob", "groups": [sync.USER_GROUP]},
            ],
            "deactivateMissingManagedAccounts": True,
        }
        users = [
            {"username": "alice", "attributes": {}},
            {"username": "old", "attributes": {"nasManagedBySetup": True}},
        ]
        with (
            mock.patch.object(sync, "authentik_list", return_value=users),
            mock.patch.object(sync, "authentik_request") as write,
        ):
            result = sync.preview_account_plan("runtime", plan)
        self.assertEqual(result["create"], ["bob"])
        self.assertEqual(result["update"], ["alice"])
        self.assertEqual(result["passwordChange"], ["alice"])
        self.assertEqual(result["deactivate"], ["old"])
        self.assertNotIn("secret", json.dumps(result))
        write.assert_not_called()

    def test_authentik_http_errors_are_redacted_and_correlated(self):
        url = "https://nas.local/identity/api/v3/core/users/?token=query-secret"
        headers = Message()
        headers["X-Request-ID"] = "upstream-123"
        error = urllib.error.HTTPError(
            url,
            403,
            "Forbidden",
            headers,
            io.BytesIO(b'{"token":"response-secret","detail":"denied"}'),
        )
        with (
            mock.patch.object(sync.urllib.request, "urlopen", side_effect=error),
            mock.patch.object(sync, "diagnostic") as diagnostic,
        ):
            with self.assertRaisesRegex(sync.SyncError, r"HTTP 403 \(reference [0-9a-f]+\)") as raised:
                sync.http_json(url)
        self.assertNotIn("query-secret", str(raised.exception))
        self.assertNotIn("response-secret", str(raised.exception))
        logged = diagnostic.call_args.args[0]
        self.assertNotIn("query-secret", logged)
        self.assertNotIn("response-secret", logged)
        self.assertIn("[redacted]", logged)

    def test_authentik_get_retries_rate_limit_then_recovers(self):
        url = "https://nas.local/identity/api/v3/core/users/"
        headers = Message()
        headers["Retry-After"] = "0"
        limited = urllib.error.HTTPError(url, 429, "Too Many Requests", headers, io.BytesIO(b'{"detail":"slow down"}'))
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok":true}'
        with (
            mock.patch.object(sync.urllib.request, "urlopen", side_effect=[limited, response]) as urlopen,
            mock.patch.object(sync.time, "sleep") as sleep,
        ):
            self.assertEqual(sync.http_json(url), {"ok": True})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(0.25)

    def test_authentik_get_retries_network_partition_then_recovers(self):
        url = "https://nas.local/identity/api/v3/core/users/"
        unavailable = urllib.error.URLError(ConnectionRefusedError("offline"))
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"[]"
        with (
            mock.patch.object(
                sync.urllib.request, "urlopen", side_effect=[unavailable, unavailable, response]
            ) as urlopen,
            mock.patch.object(sync, "_retry_delay", return_value=0.01),
            mock.patch.object(sync.time, "sleep") as sleep,
        ):
            self.assertEqual(sync.http_json(url), [])
        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_authentik_deterministic_4xx_is_not_retried(self):
        url = "https://nas.local/identity/api/v3/core/users/"
        error = urllib.error.HTTPError(url, 400, "Bad Request", Message(), io.BytesIO(b'{"detail":"bad input"}'))
        with (
            mock.patch.object(sync.urllib.request, "urlopen", side_effect=error) as urlopen,
            mock.patch.object(sync.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(sync.SyncError, "HTTP 400"):
                sync.http_json(url)
        urlopen.assert_called_once()
        sleep.assert_not_called()

    def test_authentik_mutations_are_never_replayed_automatically(self):
        url = "https://nas.local/identity/api/v3/core/groups/"
        error = urllib.error.HTTPError(url, 503, "Unavailable", Message(), io.BytesIO(b'{"detail":"retry later"}'))
        with (
            mock.patch.object(sync.urllib.request, "urlopen", side_effect=error) as urlopen,
            mock.patch.object(sync.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(sync.SyncError, "HTTP 503"):
                sync.http_json(url, method="POST", body={"name": "nas_users"})
        urlopen.assert_called_once()
        sleep.assert_not_called()

    def test_apply_accounts_cli_uses_runtime_token(self):
        plan = json.dumps({"accounts": []})
        with (
            mock.patch.object(sync.sys, "argv", ["nas-identity-sync", "apply-accounts", "-"]),
            mock.patch.object(sync.sys, "stdin", io.StringIO(plan)),
            mock.patch.object(sync, "identity_mutation_operation", return_value=mock.MagicMock()),
            mock.patch.object(sync, "acquire_lock", return_value=mock.MagicMock()),
            mock.patch.object(sync, "authentik_token", return_value="runtime-token") as token,
            mock.patch.object(sync, "apply_account_plan", return_value={"ok": True}) as apply,
        ):
            self.assertEqual(sync.main(), 0)
        token.assert_called_once_with()
        self.assertEqual(apply.call_args.args[0], "runtime-token")

    def test_read_only_status_cli_does_not_wait_for_mutation_lock(self):
        with (
            mock.patch.object(sync.sys, "argv", ["nas-identity-sync", "status"]),
            mock.patch.object(sync, "authentik_token", return_value="runtime-token"),
            mock.patch.object(sync, "load_model", return_value=mock.sentinel.model),
            mock.patch.object(sync, "model_status", return_value={"ok": True}),
            mock.patch.object(sync, "acquire_lock", side_effect=AssertionError("read-only status locked")),
        ):
            self.assertEqual(sync.main(), 0)


if __name__ == "__main__":
    unittest.main()
