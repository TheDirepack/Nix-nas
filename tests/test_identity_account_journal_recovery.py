"""Safe cancellation of failed Authentik account plans, without a live provider."""

from __future__ import annotations

import contextlib
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

import nas_identity_sync as identity  # noqa: E402
from nas_common import ADMIN_GROUP, DISABLED_GROUP, GUEST_GROUP, USER_GROUP  # noqa: E402
from nas_operation_journal import OperationJournal, load_json  # noqa: E402

FINGERPRINT = "a" * 64
NOTE = "Reviewed the partially applied account changes."


class AccountJournalCancellationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / "account.json"
        patcher = mock.patch.object(identity, "ACCOUNT_JOURNAL_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, *, status="failed", fingerprint=FINGERPRINT, step_status="failed"):
        journal = {
            "schemaVersion": 1,
            "workflow": "authentik-account-plan",
            "fingerprint": fingerprint,
            "status": status,
            "steps": {
                "account:alice": {
                    "status": step_status,
                    "result": {"email": "[EMAIL]", "password": "never-return"},
                },
            },
        }
        self.path.write_text(json.dumps(journal), encoding="utf-8")
        return journal

    def revision(self):
        record = load_json(self.path)
        assert record is not None
        return identity.account_journal_revision(record)

    def cancel(self, **overrides):
        arguments = {"fingerprint": FINGERPRINT, "revision": self.revision(), "note": NOTE}
        arguments.update(overrides)
        return identity.cancel_failed_account_plan(**arguments)

    def test_failed_plan_is_archived_before_explicit_cancellation(self):
        original = self.write()
        status = identity.account_journal_status()
        self.assertEqual(status["fingerprint"], FINGERPRINT)
        self.assertEqual(status["revision"], self.revision())
        self.assertNotIn("[EMAIL]", json.dumps(status))
        self.assertNotIn("never-return", json.dumps(status))

        result = self.cancel()
        self.assertTrue(result["cancelled"])
        archived = pathlib.Path(result["archivedJournal"])
        self.assertEqual(load_json(archived), original)
        self.assertEqual(archived.stat().st_mode & 0o777, 0o600)
        self.assertEqual(archived.parent.stat().st_mode & 0o777, 0o700)
        changed = load_json(self.path)
        assert changed is not None
        self.assertEqual(changed["status"], "cancelled")
        self.assertEqual(changed["cancelledArchive"], str(archived))
        self.assertEqual(changed["cancelNote"], NOTE)

        # A corrected plan can now be started, without lying that prior
        # Authentik side effects were undone or deleting the archived evidence.
        restarted = OperationJournal.open(self.path, workflow="authentik-account-plan", fingerprint="b" * 64)
        self.assertEqual(restarted.value["status"], "pending")
        self.assertEqual(load_json(archived), original)

    def test_cancellation_metadata_survives_a_corrected_plan(self):
        original = self.write()
        result = self.cancel()
        record_path = pathlib.Path(result["cancellationRecord"])
        record = load_json(record_path)
        assert record is not None
        self.assertEqual(record_path.parent, pathlib.Path(result["archivedJournal"]).parent)
        self.assertEqual(record_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record["fingerprint"], FINGERPRINT)
        self.assertEqual(record["note"], NOTE)
        self.assertEqual(record["journalRevision"], identity.account_journal_revision(original))
        self.assertEqual(record["archivedJournal"], result["archivedJournal"])
        self.assertIsInstance(record["cancelledAt"], int)
        self.assertEqual(record["steps"], {"account:alice": "failed"})
        # The archive stays a verbatim copy; cancellation metadata lives beside it.
        self.assertEqual(load_json(pathlib.Path(result["archivedJournal"])), original)

        OperationJournal.open(self.path, workflow="authentik-account-plan", fingerprint="b" * 64)
        self.assertEqual(load_json(self.path)["status"], "pending")  # type: ignore[index]
        self.assertEqual(load_json(record_path), record)

    def test_running_uncertain_completed_and_wrong_workflow_are_rejected(self):
        for status in ("running", "pending", "manual-recovery-required", "complete", "cancelled"):
            with self.subTest(status=status):
                original = self.write(status=status)
                with self.assertRaises(identity.SyncError):
                    self.cancel()
                self.assertEqual(load_json(self.path), original)
        for step_status in ("running", "manual-recovery-required"):
            with self.subTest(step_status=step_status):
                original = self.write(status="failed", step_status=step_status)
                with self.assertRaises(identity.SyncError):
                    self.cancel()
                self.assertEqual(load_json(self.path), original)

    def test_stale_fingerprint_revision_and_missing_note_do_not_cancel(self):
        original = self.write()
        for overrides in (
            {"fingerprint": "b" * 64},
            {"note": ""},
            {"fingerprint": "abc"},
            {"revision": "b" * 64},
            {"revision": "abc"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(identity.SyncError):
                    self.cancel(**overrides)
                self.assertEqual(load_json(self.path), original)

    def test_stale_revision_after_a_resumed_failure_is_rejected(self):
        self.write()
        inspected = self.revision()
        resumed = load_json(self.path)
        assert resumed is not None
        resumed["status"] = "failed"
        resumed["steps"]["password:alice"] = {"status": "failed", "error": "transient failure"}
        self.path.write_text(json.dumps(resumed), encoding="utf-8")

        with self.assertRaisesRegex(identity.SyncError, "state changed"):
            identity.cancel_failed_account_plan(fingerprint=FINGERPRINT, revision=inspected, note=NOTE)
        self.assertEqual(load_json(self.path), resumed)

    def test_ambiguous_mutation_is_recorded_as_manual_recovery(self):
        groups = [
            {"pk": "admin-pk", "name": ADMIN_GROUP, "users_obj": [{"pk": 1, "username": "admin"}]},
            {"pk": "user-pk", "name": USER_GROUP, "users_obj": []},
            {"pk": "guest-pk", "name": GUEST_GROUP, "users_obj": []},
            {"pk": "disabled-pk", "name": DISABLED_GROUP, "users_obj": []},
        ]
        users = [{"pk": 1, "username": "admin", "is_active": True, "groups": ["admin-pk"], "attributes": {}}]
        plan = {
            "accounts": [
                {
                    "username": "alice",
                    "name": "Alice",
                    "email": "alice@example.test",
                    "groups": [USER_GROUP],
                    "attributes": {},
                }
            ]
        }
        with (
            mock.patch.object(identity, "ensure_groups"),
            mock.patch.object(identity, "authentik_list", side_effect=[groups, users]),
            mock.patch.object(
                identity,
                "authentik_request",
                side_effect=identity.AmbiguousMutationError("upstream mutation outcome is uncertain"),
            ),
            self.assertRaises(identity.AmbiguousMutationError),
        ):
            identity.apply_account_plan("token", plan)

        journal = load_json(self.path)
        assert journal is not None
        self.assertEqual(journal["status"], "manual-recovery-required")
        self.assertEqual(journal["steps"]["account:alice"]["status"], "manual-recovery-required")
        with self.assertRaisesRegex(identity.SyncError, "Only failed account journals"):
            self.cancel(fingerprint=journal["fingerprint"])
        self.assertEqual(load_json(self.path), journal)

    def test_transport_timeouts_are_ambiguous_but_refusals_are_definitive(self):
        with mock.patch.object(identity.urllib.request, "urlopen", side_effect=TimeoutError("timed out")):
            with self.assertRaises(identity.AmbiguousMutationError):
                identity.http_json("http://authentik.invalid/api", method="POST", body={})
        refusal = identity.urllib.error.URLError(ConnectionRefusedError())
        with mock.patch.object(identity.urllib.request, "urlopen", side_effect=refusal):
            with self.assertRaises(identity.SyncError) as caught:
                identity.http_json("http://authentik.invalid/api", method="POST", body={})
        self.assertNotIsInstance(caught.exception, identity.AmbiguousMutationError)

    def test_cli_cancel_uses_identity_locks_without_live_authentik_token(self):
        self.write()
        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "nas-identity-sync",
                    "cancel-failed-accounts",
                    "--fingerprint",
                    FINGERPRINT,
                    "--revision",
                    self.revision(),
                    "--note",
                    "Reviewed provider state",
                ],
            ),
            mock.patch.object(
                identity, "identity_mutation_operation", return_value=contextlib.nullcontext()
            ) as operation,
            mock.patch.object(identity, "identity_command_lock", return_value=contextlib.nullcontext()) as lock,
            mock.patch.object(identity, "authentik_token", side_effect=AssertionError("token not needed")),
            mock.patch("sys.stdout", stdout),
        ):
            self.assertEqual(identity.main(), 0)
        operation.assert_called_once_with("identity-cancel-failed-accounts")
        lock.assert_called_once_with("cancel-failed-accounts")
        self.assertTrue(json.loads(stdout.getvalue())["cancelled"])


if __name__ == "__main__":
    unittest.main()
