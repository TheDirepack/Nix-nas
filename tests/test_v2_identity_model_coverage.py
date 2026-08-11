from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_identity_model as model  # noqa: E402


class IdentityModelCoverageTests(unittest.TestCase):
    def test_attrs_map_normalizes_scalars_lists_and_non_mappings(self) -> None:
        self.assertEqual(model.attrs_map(None), {})
        self.assertEqual(model.attrs_map({"a": 1, "b": [2]}), {"a": [1], "b": [2]})

    def test_validate_uid_rejects_non_string_and_unsafe_names(self) -> None:
        with self.assertRaisesRegex(model.SyncError, "must be a string"):
            model.validate_uid(1)  # type: ignore[arg-type]
        with self.assertRaisesRegex(model.SyncError, "not safe"):
            model.validate_uid("../escape")

    def test_group_names_accepts_names_primary_keys_and_missing_groups(self) -> None:
        groups = {"1": model.USER_GROUP, "2": model.ADMIN_GROUP}
        self.assertEqual(model.group_names({}, groups), set())
        self.assertEqual(
            model.group_names({"groups_obj": [{"name": model.USER_GROUP}, {"pk": 2}, {"pk": 99}]}, groups),
            {model.USER_GROUP, model.ADMIN_GROUP},
        )
        self.assertEqual(model.group_names({"groups": ["1", "unknown"]}, groups), {model.USER_GROUP})

    def test_build_model_ignores_malformed_rows_and_uses_group_side_membership(self) -> None:
        value = model.build_model(
            {
                "groups": [
                    {"pk": "a", "name": model.ADMIN_GROUP, "users_obj": [{"pk": 1}, {"username": "missing"}]},
                    {"pk": "u", "name": model.USER_GROUP, "users": [2]},
                    {"pk": "", "users": []},
                    "bad",
                ],
                "users": [
                    {"pk": 1, "username": "admin", "is_active": True, "groups": []},
                    {"pk": 2, "username": "alice", "is_active": True, "groups": []},
                    {"pk": 3, "is_active": True},
                    "bad",
                ],
            }
        )
        self.assertEqual(value.administrators, ("admin",))
        users = {user.uid: user for user in value.users}
        self.assertIn(model.ADMIN_GROUP, users["admin"].groups)
        self.assertIn(model.USER_GROUP, users["alice"].groups)

    def test_build_model_disables_inactive_users_and_requires_explicit_admin(self) -> None:
        with self.assertRaisesRegex(model.SyncError, "No enabled members"):
            model.build_model(
                {
                    "groups": [{"pk": "a", "name": model.ADMIN_GROUP, "users_obj": [{"username": "admin"}]}],
                    "users": [{"pk": 1, "username": "admin", "is_active": False}],
                }
            )

    def test_capability_and_model_status_are_assignment_driven(self) -> None:
        user = model.User(
            "admin",
            "admin@example.test",
            "Admin",
            frozenset({model.ADMIN_GROUP, "application.demo.access"}),
            {"nasSyncthingDevices": []},
        )
        identity = model.IdentityModel((user,), (), ("admin",))
        status = model.capability_status(identity)
        self.assertEqual(status["users"][0]["assignedApplicationCapabilities"], ["application.demo.access"])
        self.assertTrue(status["users"][0]["administratorBypass"])
        self.assertEqual(model.model_status(identity)["syncthingUsers"], [])

    def test_user_device_values_supports_singular_legacy_attribute_name_only_as_data_alias(self) -> None:
        user = model.User("alice", "a@x", "Alice", frozenset(), {"nasSyncthingDevice": ["x"]})
        self.assertEqual(model.user_device_values(user), ["x"])

    def test_desired_syncthing_skips_users_without_capability_or_devices(self) -> None:
        without_capability = model.User("a", "a@x", "A", frozenset({model.USER_GROUP}), {"nasSyncthingDevices": ["bad"]})
        without_devices = model.User(
            "b", "b@x", "B", frozenset({"application.syncthing.access"}), {"nasSyncthingDevices": []}
        )
        folders, devices = model.desired_syncthing(
            model.IdentityModel((without_capability, without_devices), (), ("a",)), pathlib.Path("/shares")
        )
        self.assertEqual((folders, devices), ({}, {}))

    def test_desired_syncthing_rejects_invalid_devices(self) -> None:
        user = model.User(
            "alice",
            "a@x",
            "Alice",
            frozenset({"application.syncthing.access"}),
            {"nasSyncthingDevices": ["not-a-device"]},
        )
        with self.assertRaisesRegex(model.SyncError, "Invalid Syncthing devices"):
            model.desired_syncthing(model.IdentityModel((user,), (), ("alice",)), pathlib.Path("/shares"))

    def test_normalized_account_plan_defaults_and_validation(self) -> None:
        value = model.normalized_account_plan({"username": "alice"}, 0)
        self.assertEqual(value["groups"], [model.USER_GROUP])
        self.assertEqual(value["name"], "alice")
        self.assertEqual(value["email"], "alice@invalid.local")
        for raw, message in [
            (None, "must be an object"),
            ({"username": "alice", "extra": True}, "unknown field"),
            ({"username": 1}, "username must be a string"),
            ({"username": "akadmin"}, "bootstrap account"),
            ({"username": "alice", "name": ""}, "name must be"),
            ({"username": "alice", "email": ""}, "email must be"),
            ({"username": "alice", "active": "yes"}, "active must be"),
            ({"username": "alice", "groups": "users"}, "groups must be"),
            ({"username": "alice", "groups": ["application.demo.access"]}, "Authentik-owned"),
            ({"username": "alice", "attributes": []}, "attributes must be"),
        ]:
            with self.subTest(raw=raw), self.assertRaisesRegex(model.SyncError, message):
                model.normalized_account_plan(raw, 0)

    def test_normalized_account_plan_role_transitions_and_password_validation(self) -> None:
        guest = model.normalized_account_plan({"username": "guest", "groups": [model.GUEST_GROUP]}, 0)
        self.assertEqual(guest["groups"], [model.GUEST_GROUP])
        disabled = model.normalized_account_plan(
            {"username": "alice", "active": False, "groups": [model.USER_GROUP, model.DISABLED_GROUP]}, 0
        )
        self.assertEqual(disabled["groups"], [model.DISABLED_GROUP])
        with self.assertRaisesRegex(model.SyncError, "cannot disable"):
            model.normalized_account_plan(
                {"username": "admin", "active": False, "groups": [model.ADMIN_GROUP]}, 0
            )
        for password in ("", "a\nb", "a\rb", "a\x00b"):
            with self.subTest(password=password), self.assertRaisesRegex(model.SyncError, "exactly one non-empty line"):
                model.normalized_account_plan({"username": "alice", "password": password}, 0)

    def test_raw_group_pks_handles_object_scalar_and_missing_groups(self) -> None:
        self.assertEqual(model.raw_group_pks({}), set())
        self.assertEqual(
            model.raw_group_pks({"groups": [{"pk": "a"}, {"num_pk": 2}, "three", {"name": "missing"}]}),
            {"a", "2", "three"},
        )

    def test_user_detail_pk_accepts_integer_and_numeric_string(self) -> None:
        self.assertEqual(model.user_detail_pk({"username": "a", "pk": 7}), 7)
        self.assertEqual(model.user_detail_pk({"username": "a", "num_pk": "8"}), 8)
        with self.assertRaisesRegex(model.SyncError, "no numeric primary key"):
            model.user_detail_pk({"username": "a", "pk": "uuid"})

    def test_enabled_administrator_names_combines_user_and_group_membership(self) -> None:
        users = [
            {"pk": 1, "username": "one", "is_active": True, "groups": ["admin-pk"]},
            {"pk": 2, "username": "two", "is_active": True, "groups": []},
            {"pk": 3, "username": "off", "is_active": False, "groups": ["admin-pk"]},
        ]
        groups = [
            {"pk": "admin-pk", "name": model.ADMIN_GROUP, "users_obj": [{"pk": 2}, {"username": "off"}]}
        ]
        self.assertEqual(model.enabled_administrator_names(users, groups), {"one", "two"})
        self.assertEqual(model.enabled_administrator_names(users, []), set())


if __name__ == "__main__":
    unittest.main()
