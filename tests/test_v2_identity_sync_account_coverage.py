from __future__ import annotations

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

import nas_identity_model as identity_model  # noqa: E402
import nas_identity_sync as sync  # noqa: E402


def base_groups() -> list[dict[str, object]]:
    return [
        {"pk": "admin-pk", "name": identity_model.ADMIN_GROUP, "users_obj": [{"pk": 1, "username": "admin"}]},
        {"pk": "user-pk", "name": identity_model.USER_GROUP, "users_obj": []},
        {"pk": "guest-pk", "name": identity_model.GUEST_GROUP, "users_obj": []},
        {"pk": "disabled-pk", "name": identity_model.DISABLED_GROUP, "users_obj": []},
        {"pk": "app-pk", "name": "application.demo.access", "users_obj": []},
    ]


def admin_user() -> dict[str, object]:
    return {
        "pk": 1,
        "username": "admin",
        "name": "Admin",
        "email": "admin@example.test",
        "is_active": True,
        "groups": ["admin-pk"],
        "attributes": {},
    }


class IdentitySyncAccountCoverageTests(unittest.TestCase):
    def journal_context(self):
        root = tempfile.TemporaryDirectory()
        patch = mock.patch.object(sync, "ACCOUNT_JOURNAL_PATH", pathlib.Path(root.name) / "account-journal.json")
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(root.cleanup)

    def test_journal_step_reuses_completed_result_and_records_failure(self) -> None:
        journal = mock.Mock()
        journal.step_complete.return_value = True
        journal.result.return_value = {"done": True}
        action = mock.Mock()
        self.assertEqual(sync.journal_step(journal, "step", action), {"done": True})
        action.assert_not_called()

        journal.step_complete.return_value = False
        action.side_effect = ValueError("boom")
        with self.assertRaisesRegex(ValueError, "boom"):
            sync.journal_step(journal, "step", action)
        journal.fail_step.assert_called_with("step", "boom")

    def test_apply_account_plan_rejects_invalid_shape_and_duplicates(self) -> None:
        cases = [
            ({"extra": True}, "unknown field"),
            ({"deactivateMissingManagedAccounts": "yes"}, "must be true or false"),
            ({"accounts": {}}, "accounts must be a list"),
            ({"accounts": [{"username": "alice"}, {"username": "alice"}]}, "Duplicate account-plan usernames"),
        ]
        for plan, message in cases:
            with self.subTest(plan=plan), self.assertRaisesRegex(sync.SyncError, message):
                sync.apply_account_plan("token", plan)

    def test_apply_account_plan_creates_user_and_sets_password(self) -> None:
        self.journal_context()
        groups = base_groups()
        users = [admin_user()]
        calls: list[tuple[str, dict[str, object]]] = []

        def request(_token: str, path: str, **kwargs: object) -> dict[str, object]:
            calls.append((path, kwargs))
            if path == "core/users/":
                return {"pk": 42, "username": "alice"}
            return {}

        plan = {
            "accounts": [
                {
                    "username": "alice",
                    "name": "Alice",
                    "email": "alice@example.test",
                    "groups": [identity_model.USER_GROUP],
                    "attributes": {"department": "home"},
                    "password": "temporary-secret",
                }
            ]
        }
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(sync, "authentik_request", side_effect=request),
        ):
            result = sync.apply_account_plan("token", plan)
        self.assertEqual(result["created"], ["alice"])
        self.assertEqual(result["passwordsChanged"], ["alice"])
        create = next(kwargs for path, kwargs in calls if path == "core/users/")
        self.assertEqual(create["body"]["type"], "internal")
        self.assertTrue(create["body"]["attributes"]["nasManagedBySetup"])
        password = next(kwargs for path, kwargs in calls if path == "core/users/42/set_password/")
        self.assertEqual(password["body"], {"password": "temporary-secret"})
        self.assertNotIn("temporary-secret", json.dumps(result))

    def test_apply_account_plan_updates_user_and_preserves_application_assignment(self) -> None:
        self.journal_context()
        groups = base_groups()
        users = [
            admin_user(),
            {
                "pk": 7,
                "username": "alice",
                "name": "Old",
                "email": "old@example.test",
                "is_active": True,
                "groups": ["user-pk", "app-pk"],
                "attributes": {"existing": "kept", "nasManagedBySetup": True},
            },
        ]
        calls: list[tuple[str, dict[str, object]]] = []
        plan = {
            "accounts": [
                {
                    "username": "alice",
                    "name": "Alice",
                    "email": "alice@example.test",
                    "groups": [identity_model.USER_GROUP],
                    "attributes": {"new": "value"},
                }
            ]
        }
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(sync, "authentik_request", side_effect=lambda _token, path, **kwargs: calls.append((path, kwargs)) or {}),
        ):
            result = sync.apply_account_plan("token", plan)
        self.assertEqual(result["updated"], ["alice"])
        patch = next(kwargs for path, kwargs in calls if path == "core/users/7/")
        self.assertIn("app-pk", patch["body"]["groups"])
        self.assertIn("user-pk", patch["body"]["groups"])
        self.assertEqual(patch["body"]["attributes"]["existing"], "kept")
        self.assertEqual(patch["body"]["attributes"]["new"], "value")

    def test_apply_account_plan_deactivates_only_setup_managed_missing_users(self) -> None:
        self.journal_context()
        groups = base_groups()
        users = [
            admin_user(),
            {
                "pk": 8,
                "username": "old-managed",
                "is_active": True,
                "groups": ["user-pk", "app-pk"],
                "attributes": {"nasManagedBySetup": True},
            },
            {
                "pk": 9,
                "username": "manual",
                "is_active": True,
                "groups": ["user-pk"],
                "attributes": {},
            },
        ]
        calls: list[tuple[str, dict[str, object]]] = []
        plan = {
            "accounts": [
                {
                    "username": "admin",
                    "name": "Admin",
                    "email": "admin@example.test",
                    "groups": [identity_model.ADMIN_GROUP],
                }
            ],
            "deactivateMissingManagedAccounts": True,
        }
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(sync, "authentik_request", side_effect=lambda _token, path, **kwargs: calls.append((path, kwargs)) or {}),
        ):
            result = sync.apply_account_plan("token", plan)
        self.assertEqual(result["deactivated"], ["old-managed"])
        deactivation = next(kwargs for path, kwargs in calls if path == "core/users/8/")
        self.assertFalse(deactivation["body"]["is_active"])
        self.assertIn("disabled-pk", deactivation["body"]["groups"])
        self.assertIn("app-pk", deactivation["body"]["groups"])
        self.assertFalse(any(path == "core/users/9/" for path, _ in calls))

    def test_apply_account_plan_rejects_admin_lockout_and_missing_reserved_roles(self) -> None:
        self.journal_context()
        groups = base_groups()
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", side_effect=[groups, [admin_user()]]),
        ):
            with self.assertRaisesRegex(sync.SyncError, "leave no enabled members"):
                sync.apply_account_plan("token", {"accounts": [{"username": "admin", "active": False}]})

        self.journal_context()
        missing = [row for row in groups if row["name"] != identity_model.DISABLED_GROUP]
        with (
            mock.patch.object(sync, "ensure_groups"),
            mock.patch.object(sync, "authentik_list", return_value=missing),
        ):
            with self.assertRaisesRegex(sync.SyncError, "Reserved groups are missing"):
                sync.apply_account_plan("token", {"accounts": []})

    def test_preview_account_plan_classifies_create_update_password_and_deactivate(self) -> None:
        users = [
            admin_user(),
            {"pk": 2, "username": "alice", "attributes": {}},
            {"pk": 3, "username": "old", "attributes": {"nasManagedBySetup": True}},
            {"pk": 4, "username": "manual", "attributes": {}},
        ]
        plan = {
            "accounts": [
                {"username": "alice", "password": "new-secret"},
                {"username": "bob"},
            ],
            "deactivateMissingManagedAccounts": True,
        }
        with mock.patch.object(sync, "authentik_list", return_value=users):
            result = sync.preview_account_plan("token", plan)
        self.assertEqual(result["create"], ["bob"])
        self.assertEqual(result["update"], ["alice"])
        self.assertEqual(result["passwordChange"], ["alice"])
        self.assertEqual(result["deactivate"], ["old"])
        self.assertFalse(result["applied"])
        with self.assertRaisesRegex(sync.SyncError, "accounts must be a list"):
            sync.preview_account_plan("token", {"accounts": {}})

    def test_export_account_reports_only_base_roles_and_safe_attributes(self) -> None:
        users = [
            {
                "pk": 7,
                "username": "alice",
                "name": "Alice",
                "email": "alice@example.test",
                "is_active": True,
                "groups": ["user-pk", "app-pk"],
                "attributes": {"x": 1},
            }
        ]
        with mock.patch.object(sync, "authentik_list", side_effect=[users, base_groups()]):
            result = sync.export_account("token", "alice")
        self.assertEqual(result["groups"], [identity_model.USER_GROUP])
        self.assertEqual(result["attributes"], {"x": 1})
        with mock.patch.object(sync, "authentik_list", side_effect=[[], base_groups()]):
            with self.assertRaisesRegex(sync.SyncError, "does not exist"):
                sync.export_account("token", "alice")

    def test_reconcile_syncthing_mutates_removes_verifies_and_restarts(self) -> None:
        device_id = "DEVICE"
        folders = {"folder": {"id": "folder", "path": "/shares/users/alice/syncthing", "type": "receiveonly"}}
        devices = {device_id: {"deviceID": device_id, "name": "Alice"}}
        identity = identity_model.IdentityModel((), (), ("admin",))
        calls: list[tuple[str, str, object]] = []

        def request(path: str, *, method: str = "GET", body: object = None) -> object:
            calls.append((path, method, body))
            if path == "/rest/config/folders":
                return list(folders.values())
            if path == "/rest/config/devices":
                return list(devices.values())
            if path == "/rest/config/restart-required":
                return {"requiresRestart": True}
            return {}

        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state = root / "state.json"
            state.write_text('{"folders":["old-folder"],"devices":["OLD-DEVICE"]}', encoding="utf-8")
            journal = root / "journal.json"
            with (
                mock.patch.object(sync, "SYNCTHING_ENABLED", True),
                mock.patch.object(sync, "STATE_PATH", state),
                mock.patch.object(sync, "SYNCTHING_JOURNAL_PATH", journal),
                mock.patch.object(sync, "desired_syncthing", return_value=(folders, devices)),
                mock.patch.object(sync, "ensure_syncthing_folder"),
                mock.patch.object(sync, "syncthing_request", side_effect=request),
            ):
                result = sync.reconcile_syncthing(identity)
            self.assertEqual(result["removedFolders"], 1)
            self.assertEqual(result["removedDevices"], 1)
            self.assertFalse(journal.exists())
            committed = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(committed["folders"], ["folder"])
            self.assertEqual(committed["devices"], [device_id])
            self.assertIn(("/rest/system/restart", "POST", None), calls)
            self.assertTrue(any(path.endswith("old-folder") and method == "DELETE" for path, method, _ in calls))

    def test_reconcile_syncthing_retains_still_referenced_device(self) -> None:
        identity = identity_model.IdentityModel((), (), ("admin",))
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state = root / "state.json"
            state.write_text('{"folders":[],"devices":["OLD"]}', encoding="utf-8")
            journal = root / "journal.json"

            def request(path: str, *, method: str = "GET", body: object = None) -> object:
                if path.endswith("/OLD") and method == "DELETE":
                    raise sync.SyncError("HTTP 409 still referenced")
                if path in {"/rest/config/folders", "/rest/config/devices"}:
                    return []
                if path == "/rest/config/restart-required":
                    return {"requiresRestart": False}
                return {}

            with (
                mock.patch.object(sync, "SYNCTHING_ENABLED", True),
                mock.patch.object(sync, "STATE_PATH", state),
                mock.patch.object(sync, "SYNCTHING_JOURNAL_PATH", journal),
                mock.patch.object(sync, "desired_syncthing", return_value=({}, {})),
                mock.patch.object(sync, "syncthing_request", side_effect=request),
            ):
                result = sync.reconcile_syncthing(identity)
            self.assertEqual(result["removedDevices"], 0)
            self.assertEqual(json.loads(state.read_text(encoding="utf-8"))["devices"], ["OLD"])

    def test_atomic_write_and_remove_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "state.json"
            self.assertTrue(sync.atomic_write(path, "one\n"))
            self.assertFalse(sync.atomic_write(path, "one\n"))
            self.assertTrue(sync.atomic_write_json(path, {"value": 2}))
            sync.remove_file_durable(path)
            self.assertFalse(path.exists())
            sync.remove_file_durable(path)

    def test_object_index_and_expected_subset_validation(self) -> None:
        with self.assertRaisesRegex(sync.SyncError, "did not return a list"):
            sync.object_by_identifier({}, "id", label="folder")
        with self.assertRaisesRegex(sync.SyncError, "invalid object"):
            sync.object_by_identifier([{}], "id", label="folder")
        with self.assertRaisesRegex(sync.SyncError, "duplicate identifier"):
            sync.object_by_identifier([{"id": "a"}, {"id": "a"}], "id", label="folder")
        self.assertTrue(sync.expected_subset({"devices": [{"deviceID": "A"}, {"deviceID": "B"}]}, {"devices": [{"deviceID": "A"}]}))
        self.assertFalse(sync.expected_subset([], {}))
        self.assertFalse(sync.expected_subset({}, []))
        self.assertTrue(sync.expected_subset([1], [1]))


if __name__ == "__main__":
    unittest.main()
