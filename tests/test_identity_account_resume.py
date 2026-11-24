"""Account-plan retries against live provider state and an on-disk journal."""

from __future__ import annotations

import copy
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_identity_sync as identity  # noqa: E402
from nas_operation_journal import load_json  # noqa: E402


class AccountApi:
    def __init__(self):
        self.users = {
            "alice": {
                "pk": 1,
                "username": "alice",
                "name": "Alice",
                "email": "alice@example.test",
                "is_active": True,
                "groups": ["admin", "app"],
                "attributes": {"nasManagedBySetup": True},
            },
            "bob": {
                "pk": 2,
                "username": "bob",
                "name": "Bob",
                "email": "bob@example.test",
                "is_active": True,
                "groups": ["users", "app"],
                "attributes": {},
            },
        }
        self.calls = []
        self.fail_update = True
        self.fail_user = "alice"
        self.ignore_bob = False
        self.passwords = []
        self.lose_bob_on_alice = False

    def listing(self, token, path):
        if path == "core/users/?include_groups=true":
            return copy.deepcopy(list(self.users.values()))
        if path == "core/groups/?include_users=true":
            return [
                {"pk": pk, "name": name, "users": [u["pk"] for u in self.users.values() if pk in u["groups"]]}
                for pk, name in (
                    ("admin", "nas_admin"),
                    ("users", "nas_users"),
                    ("guest", "nas_guests"),
                    ("disabled", "nas_disabled"),
                    ("app", "application.demo.access"),
                )
            ]
        raise AssertionError(path)

    def request(self, token, path, *, method, body):
        self.calls.append((path, method, copy.deepcopy(body)))
        user = next(u for u in self.users.values() if path.startswith(f"core/users/{u['pk']}/"))
        if path.endswith("set_password/"):
            self.passwords.append(user["username"])
            return {}
        if user["username"] == self.fail_user and self.fail_update:
            self.fail_update = False
            raise identity.SyncError(f"HTTP 400 {user['name']} update rejected")
        if not (self.ignore_bob and user["username"] == "bob"):
            user.update(copy.deepcopy(body))
        if self.lose_bob_on_alice and user["username"] == "alice":
            self.users["bob"]["groups"] = ["users", "app"]
        return copy.deepcopy(user)

    def administrators(self):
        return sorted(u["username"] for u in self.users.values() if u["is_active"] and "admin" in u["groups"])


class AccountPlanResumeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = pathlib.Path(temporary.name) / "account.json"
        self.api = AccountApi()
        for patcher in (
            mock.patch.object(identity, "ACCOUNT_JOURNAL_PATH", self.path),
            mock.patch.object(identity, "ensure_groups"),
            mock.patch.object(identity, "authentik_list", side_effect=self.api.listing),
            mock.patch.object(identity, "authentik_request", side_effect=self.api.request),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def journal(self):
        value = load_json(self.path)
        assert value is not None, "Account-plan journal was not persisted"
        return value

    def plan(self, *, deactivate_missing=False, password=False):
        bob = {"username": "bob", "name": "Bob", "email": "bob@example.test", "groups": ["nas_admin"]}
        if password:
            bob["password"] = "transient-replacement-secret"
        alice = {"username": "alice", "name": "Alice", "email": "alice@example.test", "groups": ["nas_users"]}
        return {
            "accounts": [bob] if deactivate_missing else [alice, bob],
            "deactivateMissingManagedAccounts": deactivate_missing,
        }

    def interrupted(self, plan):
        with self.assertRaisesRegex(identity.SyncError, "Alice update rejected"):
            identity.apply_account_plan("token", plan)
        journal = self.journal()
        self.assertEqual(journal["status"], "failed")
        self.assertEqual(journal["steps"]["account:bob"]["status"], "complete")
        self.assertEqual(self.api.administrators(), ["alice", "bob"])
        self.api.calls.clear()

    def test_resume_revalidates_completed_replacement_before_demotion_or_deactivation(self):
        for deactivate in (False, True):
            for drift in ("grant", "disabled", "profile"):
                with self.subTest(deactivate=deactivate, drift=drift):
                    self.path.unlink(missing_ok=True)
                    self.api.__init__()
                    plan = self.plan(deactivate_missing=deactivate)
                    self.interrupted(plan)
                    bob = self.api.users["bob"]
                    if drift == "grant":
                        bob["groups"] = ["users", "app"]
                    elif drift == "disabled":
                        bob["is_active"] = False
                    else:
                        bob["email"] = "external@example.test"
                    with self.assertRaisesRegex(identity.SyncError, "bob.*drift|drift.*bob"):
                        identity.apply_account_plan("token", plan)
                    self.assertIn("alice", self.api.administrators())
                    self.assertEqual(self.api.calls, [])
                    self.assertEqual(self.journal()["status"], "failed")
                    self.assertIn("app", bob["groups"])

    def test_no_drift_resume_skips_structural_write_and_reports_live_admins(self):
        for deactivate in (False, True):
            with self.subTest(deactivate=deactivate):
                self.path.unlink(missing_ok=True)
                self.api.__init__()
                plan = self.plan(deactivate_missing=deactivate)
                self.interrupted(plan)
                self.api.users["bob"]["groups"].append("operator-application-grant")
                self.api.users["bob"]["attributes"]["external"] = "preserved"
                result = identity.apply_account_plan("token", plan)
                self.assertEqual(result["administrators"], self.api.administrators())
                self.assertEqual(result["administrators"], ["bob"])
                self.assertFalse(any(path == "core/users/2/" for path, _, _ in self.api.calls))
                self.assertIn("app", self.api.users["alice"]["groups"])
                self.assertIn("app", self.api.users["bob"]["groups"])
                self.assertIn("operator-application-grant", self.api.users["bob"]["groups"])
                self.assertEqual(self.journal()["status"], "complete")

    def test_resume_rejects_drift_inside_plan_owned_attribute_values(self):
        plan = self.plan()
        accounts = plan["accounts"]
        assert isinstance(accounts, list)
        accounts[1]["attributes"] = {"preferences": {"labels": []}}
        self.interrupted(plan)
        self.api.users["bob"]["attributes"]["preferences"]["labels"].append("changed")
        with self.assertRaisesRegex(identity.SyncError, "structural drift for bob"):
            identity.apply_account_plan("token", plan)
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.api.administrators(), ["alice", "bob"])

    def test_unapplied_promotion_cannot_authorize_demotion_or_deactivation(self):
        for deactivate in (False, True):
            with self.subTest(deactivate=deactivate):
                self.path.unlink(missing_ok=True)
                self.api.__init__()
                self.api.ignore_bob = True
                self.api.fail_update = False
                with self.assertRaisesRegex(identity.SyncError, "administrator|nas_admin"):
                    identity.apply_account_plan("token", self.plan(deactivate_missing=deactivate))
                self.assertEqual(self.api.administrators(), ["alice"])
                self.assertFalse(any(path == "core/users/1/" for path, _, _ in self.api.calls))
                self.assertNotEqual(self.journal()["status"], "complete")

    def interrupted_deactivations(self):
        self.api.users["carol"] = {
            **self.api.users["alice"],
            "pk": 3,
            "username": "carol",
            "name": "Carol",
            "groups": ["users", "app"],
        }
        self.api.fail_user = "carol"
        plan = self.plan(deactivate_missing=True)
        with self.assertRaisesRegex(identity.SyncError, "Carol update rejected"):
            identity.apply_account_plan("token", plan)
        self.assertEqual(self.journal()["steps"]["deactivate:alice"]["status"], "complete")
        self.assertFalse(self.api.users["alice"]["is_active"])
        self.api.calls.clear()
        return plan

    def test_resume_stops_before_pending_writes_when_completed_deactivation_drifted(self):
        for drift in ("reactivated", "admin grant", "unmanaged", "removed"):
            with self.subTest(drift=drift):
                self.path.unlink(missing_ok=True)
                self.api.__init__()
                plan = self.interrupted_deactivations()
                alice = self.api.users["alice"]
                if drift == "reactivated":
                    alice["is_active"] = True
                elif drift == "admin grant":
                    alice["groups"].append("admin")
                elif drift == "unmanaged":
                    alice["attributes"] = {}
                else:
                    del self.api.users["alice"]
                with self.assertRaisesRegex(identity.SyncError, "structural drift for alice"):
                    identity.apply_account_plan("token", plan)
                self.assertEqual(self.api.calls, [])
                self.assertEqual(self.journal()["status"], "failed")

    def test_resume_preserves_completed_deactivation_with_unrelated_changes(self):
        plan = self.interrupted_deactivations()
        self.api.users["alice"]["groups"].append("operator-application-grant")
        self.api.users["alice"]["attributes"]["external"] = "preserved"
        result = identity.apply_account_plan("token", plan)
        self.assertEqual(result["deactivated"], ["alice", "carol"])
        self.assertEqual(result["administrators"], ["bob"])
        self.assertEqual([path for path, _, _ in self.api.calls], ["core/users/3/"])

    def test_final_readback_cannot_report_an_administrator_who_lost_access(self):
        plan = self.plan()
        self.interrupted(plan)
        self.api.lose_bob_on_alice = True
        with self.assertRaisesRegex(identity.SyncError, "administrator|nas_admin"):
            identity.apply_account_plan("token", plan)
        self.assertEqual(self.api.administrators(), [])
        self.assertEqual(self.journal()["status"], "failed")

    def test_password_resume_requires_confirmation_even_without_structural_drift(self):
        plan = self.plan(password=True)
        self.interrupted(plan)
        self.assertEqual(self.api.passwords, ["bob"])
        before = self.path.read_bytes()
        with self.assertRaisesRegex(identity.SyncError, "confirm-password-reapply"):
            identity.apply_account_plan("token", plan)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.api.calls, [])
        self.api.users["bob"]["is_active"] = False
        with self.assertRaisesRegex(identity.SyncError, "structural drift"):
            identity.apply_account_plan("token", plan, confirm_password_reapply=True)
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.api.passwords, ["bob"])
        self.api.users["bob"]["is_active"] = True
        result = identity.apply_account_plan("token", plan, confirm_password_reapply=True)
        self.assertEqual(self.api.passwords, ["bob", "bob"])
        self.assertEqual(result["administrators"], self.api.administrators())
        self.assertNotIn("transient-replacement-secret", self.path.read_text())
