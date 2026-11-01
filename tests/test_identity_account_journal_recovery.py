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
from nas_operation_journal import OperationJournal, load_json  # noqa: E402

FINGERPRINT = "a" * 64


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
                    "result": {"email": "private@example.invalid", "password": "never-return"},
                },
            },
        }
        self.path.write_text(json.dumps(journal), encoding="utf-8")
        return journal

    def test_failed_plan_is_archived_before_explicit_cancellation(self):
        original = self.write()
        status = identity.account_journal_status()
        self.assertEqual(status["fingerprint"], FINGERPRINT)
        self.assertNotIn("private@example.invalid", json.dumps(status))
        self.assertNotIn("never-return", json.dumps(status))

        result = identity.cancel_failed_account_plan(
            fingerprint=FINGERPRINT, note="Reviewed the partially applied account changes."
        )
        self.assertTrue(result["cancelled"])
        archived = pathlib.Path(result["archivedJournal"])
        self.assertEqual(load_json(archived), original)
        self.assertEqual(archived.stat().st_mode & 0o777, 0o600)
        self.assertEqual(archived.parent.stat().st_mode & 0o777, 0o700)
        changed = load_json(self.path)
        assert changed is not None
        self.assertEqual(changed["status"], "cancelled")
        self.assertEqual(changed["cancelledArchive"], str(archived))
        self.assertEqual(changed["cancelNote"], "Reviewed the partially applied account changes.")

        # A corrected plan can now be started, without lying that prior
        # Authentik side effects were undone or deleting the archived evidence.
        restarted = OperationJournal.open(self.path, workflow="authentik-account-plan", fingerprint="b" * 64)
        self.assertEqual(restarted.value["status"], "pending")
        self.assertEqual(load_json(archived), original)

    def test_running_uncertain_completed_and_wrong_workflow_are_rejected(self):
        for status in ("running", "pending", "manual-recovery-required", "complete", "cancelled"):
            with self.subTest(status=status):
                original = self.write(status=status)
                with self.assertRaises(identity.SyncError):
                    identity.cancel_failed_account_plan(fingerprint=FINGERPRINT, note="checked")
                self.assertEqual(load_json(self.path), original)
        original = self.write(status="failed", step_status="running")
        with self.assertRaisesRegex(identity.SyncError, "unverified or running"):
            identity.cancel_failed_account_plan(fingerprint=FINGERPRINT, note="checked")
        self.assertEqual(load_json(self.path), original)

    def test_stale_fingerprint_and_missing_note_do_not_cancel(self):
        original = self.write()
        for fingerprint, note in (("b" * 64, "reviewed"), (FINGERPRINT, ""), ("abc", "reviewed")):
            with self.subTest(fingerprint=fingerprint, note=note):
                with self.assertRaises(identity.SyncError):
                    identity.cancel_failed_account_plan(fingerprint=fingerprint, note=note)
                self.assertEqual(load_json(self.path), original)

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
