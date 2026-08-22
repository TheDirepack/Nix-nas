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

FIXTURE = ROOT / "tests" / "fixtures" / "authentik-identity.json"


class IdentityModelTests(unittest.TestCase):
    def model(self) -> identity_model.IdentityModel:
        return sync.fixture_model(FIXTURE)

    def test_fixture_is_v2_native_and_excludes_disabled_users(self) -> None:
        model = self.model()
        self.assertEqual([user.uid for user in model.users], ["admin", "alice", "guest"])
        self.assertEqual(model.administrators, ("admin",))
        self.assertEqual(sync.model_status(model)["capabilityModel"], "managed-services-v2")

    def test_retire_bootstrap_administrator_requires_a_verified_replacement_then_deletes_akadmin(self) -> None:
        groups = [{"pk": "admins", "name": "nas_admin", "users_obj": [{"pk": 2}]}]
        users = [
            {"username": "akadmin", "pk": 1, "is_active": True, "groups": ["admins"]},
            {"username": "nasadmin", "pk": 2, "is_active": True, "groups": ["admins"]},
        ]
        with (
            mock.patch.object(sync, "authentik_list", side_effect=[users, groups]),
            mock.patch.object(sync, "authentik_request") as request,
        ):
            result = sync.retire_bootstrap_administrator("runtime-token", "nasadmin")
        self.assertEqual(result, {"retiredBootstrapAdministrator": "akadmin", "verifiedAdministrator": "nasadmin"})
        request.assert_called_once_with("runtime-token", "core/users/1/", method="DELETE")

    def test_capability_report_uses_canonical_authentik_assignments(self) -> None:
        report = identity_model.capability_status(self.model())
        users = {row["id"]: row for row in report["users"]}
        self.assertEqual(report["capabilityModel"], "managed-services-v2")
        self.assertIn("application.ai-workspace.access", users["admin"]["capabilities"])
        self.assertIn("application.vaultwarden.access", users["alice"]["capabilities"])
        self.assertIn("application.syncthing.access", users["alice"]["capabilities"])
        self.assertEqual(users["guest"]["capabilities"], {})
        for row in users.values():
            self.assertNotIn("nas_allow_ai", row["groups"])
            self.assertNotIn("nas_allow_syncthing", row["groups"])

    def test_syncthing_devices_are_authentik_attributes_plus_v2_capability(self) -> None:
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(sync, "SHARE_ROOT", pathlib.Path(raw)):
            folders, devices = sync.desired_syncthing(self.model())
        self.assertEqual(set(folders), {"nas-admin-backup", "nas-alice-backup"})
        self.assertEqual(len(devices), 2)
        self.assertEqual(folders["nas-alice-backup"]["type"], "receiveonly")
        self.assertEqual(folders["nas-alice-backup"]["pullerMaxPendingKiB"], 16384)

    def test_syncthing_access_is_not_inferred_from_old_groups(self) -> None:
        user = identity_model.User(
            "alice",
            "alice@example.test",
            "Alice",
            frozenset({identity_model.USER_GROUP, "nas_allow_syncthing"}),
            {
                "nasSyncthingDevices": [
                    json.dumps({"id": "IIIIIII-JJJJJJJ-KKKKKKK-LLLLLLL-MMMMMMM-NNNNNNN-OOOOOOO-PPPPPPP"})
                ]
            },
        )
        self.assertFalse(user.personal_sync)

    def test_conflicting_syncthing_device_definitions_fail_closed(self) -> None:
        device_id = "IIIIIII-JJJJJJJ-KKKKKKK-LLLLLLL-MMMMMMM-NNNNNNN-OOOOOOO-PPPPPPP"
        attrs_a = {"nasSyncthingDevices": [json.dumps({"id": device_id, "name": "A"})]}
        attrs_b = {"nasSyncthingDevices": [json.dumps({"id": device_id, "name": "B"})]}
        groups = frozenset({"application.syncthing.access"})
        model = identity_model.IdentityModel(
            (
                identity_model.User("a", "a@example.test", "A", groups, attrs_a),
                identity_model.User("b", "b@example.test", "B", groups, attrs_b),
            ),
            (),
            ("a",),
        )
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(identity_model.SyncError, "conflicting Authentik definitions"):
                identity_model.desired_syncthing(model, pathlib.Path(raw))

    def test_build_model_requires_explicit_enabled_nas_admin(self) -> None:
        with self.assertRaisesRegex(identity_model.SyncError, "No enabled members of nas_admin"):
            identity_model.build_model(
                {
                    "users": [
                        {
                            "pk": 1,
                            "username": "alice",
                            "is_active": True,
                            "groups_obj": [{"name": "nas_users"}],
                        }
                    ],
                    "groups": [{"pk": "users", "name": "nas_users", "users_obj": [{"username": "alice"}]}],
                }
            )

    def test_account_plan_accepts_only_base_roles(self) -> None:
        normalized = identity_model.normalized_account_plan(
            {"username": "alice", "groups": [identity_model.USER_GROUP]},
            0,
        )
        self.assertEqual(normalized["groups"], [identity_model.USER_GROUP])
        with self.assertRaisesRegex(identity_model.SyncError, "application capability assignments are Authentik-owned"):
            identity_model.normalized_account_plan(
                {"username": "alice", "groups": ["application.syncthing.access"]},
                0,
            )

    def test_inactive_account_plan_collapses_to_disabled_role(self) -> None:
        normalized = identity_model.normalized_account_plan(
            {"username": "alice", "active": False, "groups": [identity_model.USER_GROUP]},
            0,
        )
        self.assertEqual(normalized["groups"], [identity_model.DISABLED_GROUP])
        with self.assertRaisesRegex(identity_model.SyncError, "cannot disable"):
            identity_model.normalized_account_plan(
                {"username": "alice", "active": False, "groups": [identity_model.ADMIN_GROUP]},
                0,
            )

    def test_akadmin_is_not_managed_by_account_plans(self) -> None:
        with self.assertRaisesRegex(identity_model.SyncError, "bootstrap account"):
            identity_model.normalized_account_plan({"username": "akadmin"}, 0)


class IdentitySyncTests(unittest.TestCase):
    def test_ensure_groups_reconciles_only_base_identity_roles(self) -> None:
        existing = [
            {"pk": name, "name": name, "is_superuser": name == identity_model.ADMIN_GROUP}
            for name in identity_model.RESERVED_GROUPS
        ]
        refreshed = [
            {
                **row,
                "users_obj": ([{"username": "admin"}] if row["name"] == identity_model.ADMIN_GROUP else []),
            }
            for row in existing
        ]
        with (
            mock.patch.object(sync, "authentik_list", side_effect=[existing, refreshed]),
            mock.patch.object(sync, "authentik_request") as request,
        ):
            result = sync.ensure_groups("token")
        self.assertEqual(result["createdGroups"], [])
        self.assertEqual(result["correctedSuperuserGroups"], [])
        self.assertIsNone(result["bootstrappedAdministrator"])
        request.assert_not_called()

    def test_verify_token_reports_reserved_group_presence(self) -> None:
        groups = [{"name": name} for name in identity_model.RESERVED_GROUPS]
        with mock.patch.object(sync, "authentik_list", side_effect=[[{"username": "admin"}], groups]):
            result = sync.verify_token("token")
        self.assertTrue(result["ok"])
        self.assertEqual(result["reservedGroupsMissing"], [])
        self.assertEqual(result["reservedGroupsPresent"], sorted(identity_model.RESERVED_GROUPS))

    def test_fixture_loader_rejects_non_object_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "fixture.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(identity_model.SyncError, "Fixture must contain"):
                sync.fixture_model(path)

    def test_state_loader_is_fail_closed_for_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "state.json"
            with mock.patch.object(sync, "STATE_PATH", path):
                self.assertEqual(sync.load_state(), {"folders": [], "devices": []})
                path.write_text("{", encoding="utf-8")
                with self.assertRaisesRegex(identity_model.SyncError, "Invalid identity sync state"):
                    sync.load_state()

    def test_atomic_write_json_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "state.json"
            self.assertTrue(sync.atomic_write_json(path, {"value": 1}))
            self.assertFalse(sync.atomic_write_json(path, {"value": 1}))
            self.assertTrue(sync.atomic_write_json(path, {"value": 2}))
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"value": 2})

    def test_syncthing_object_index_rejects_duplicates_and_malformed_rows(self) -> None:
        with self.assertRaisesRegex(identity_model.SyncError, "duplicate identifier"):
            sync.object_by_identifier([{"id": "a"}, {"id": "a"}], "id", label="folder")
        with self.assertRaisesRegex(identity_model.SyncError, "invalid object"):
            sync.object_by_identifier([{"missing": "id"}], "id", label="folder")

    def test_expected_subset_matches_device_sets_by_id(self) -> None:
        observed = {"devices": [{"deviceID": "A"}, {"deviceID": "B"}], "type": "receiveonly"}
        expected = {"devices": [{"deviceID": "A"}], "type": "receiveonly"}
        self.assertTrue(sync.expected_subset(observed, expected))
        self.assertFalse(sync.expected_subset(observed, {"type": "sendonly"}))

    def test_syncthing_api_key_prefers_dedicated_file_then_config_xml(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with mock.patch.object(sync, "SYNCTHING_CONFIG_DIR", root):
                (root / "apikey").write_text("dedicated\n", encoding="utf-8")
                self.assertEqual(sync.syncthing_api_key(), "dedicated")
                (root / "apikey").unlink()
                (root / "config.xml").write_text(
                    "<configuration><apikey>xml-key</apikey></configuration>", encoding="utf-8"
                )
                self.assertEqual(sync.syncthing_api_key(), "xml-key")

    def test_source_never_reintroduces_copyparty_or_legacy_capability_authority(self) -> None:
        source = (ROOT / "services" / "nas_identity_sync.py").read_text(encoding="utf-8")
        model = (ROOT / "services" / "nas_identity_model.py").read_text(encoding="utf-8")
        self.assertNotIn("render_copyparty", source)
        self.assertNotIn("nas_allow_files", source + model)
        self.assertNotIn("nas_allow_syncthing", source + model)
        self.assertIn("Managed Services V2", source)
        self.assertIn("application_capability_allowed", model)

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
