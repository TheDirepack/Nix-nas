"""Guard direct and detached first-run execution against completed appliance state."""

from __future__ import annotations

import argparse
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

import nas_operation_journal as journal  # noqa: E402
import nas_setup as setup  # noqa: E402


class FirstRunCompletionGuardTests(unittest.TestCase):
    def check(self, state=None, journal=None, *, corrupt_state=False, should_block: bool):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_path = root / "state.json"
            journal_path = root / "journal.json"
            if corrupt_state:
                state_path.write_text("{invalid-json", encoding="utf-8")
            elif state is not None:
                state_path.write_text(json.dumps(state), encoding="utf-8")
            if journal is not None:
                journal_path.write_text(json.dumps(journal), encoding="utf-8")

            with (
                mock.patch.object(setup, "STATE_PATH", state_path),
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
                mock.patch.object(setup, "normalize_config") as normalize,
            ):
                if should_block:
                    with self.assertRaisesRegex(setup.SetupError, "first-run|Cannot verify"):
                        setup._first_run_locked(argparse.Namespace())
                    # Must fail before any storage, credentials or identity mutation.
                    normalize.assert_not_called()
                else:
                    setup.reject_completed_first_run()
                    normalize.assert_not_called()

    def test_completed_state_forbids_direct_cli_reentry(self):
        for status in ("complete", "complete-unverified"):
            with self.subTest(status=status):
                self.check(state={"schemaVersion": 2, "status": status}, should_block=True)

    def test_completed_journal_forbids_reentry_even_if_state_missing(self):
        self.check(
            journal={"schemaVersion": 1, "workflow": "first-run-v2", "status": "complete"},
            should_block=True,
        )

    def test_completed_journal_with_altered_or_missing_identity_still_blocks(self):
        for record in (
            {"schemaVersion": 1, "workflow": "other-workflow", "status": "complete"},
            {"schemaVersion": 1, "status": "complete"},
            {"schemaVersion": 7, "workflow": "first-run-v2", "status": "complete"},
            {"schemaVersion": 1, "workflow": "", "status": "complete"},
        ):
            with self.subTest(journal=record):
                self.check(journal=record, should_block=True)

    def test_completed_journal_with_unsupported_schema_cannot_replace_itself(self):
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "journal.json"
            path.write_text(
                json.dumps({"schemaVersion": 7, "workflow": "first-run-v2", "status": "complete"}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(journal.JournalError, "schemaVersion"):
                journal.OperationJournal.open(path, workflow="identity-sync", fingerprint="fingerprint")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["schemaVersion"], 7)

    def test_crash_between_state_write_and_final_state_record_still_recovers(self):
        report = {"schemaVersion": 2, "status": "complete", "planDigest": "digest"}
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_path = root / "state.json"
            journal_path = root / "journal.json"
            state_path.write_text(json.dumps(report), encoding="utf-8")
            # The process died after publishing state but before the final-state
            # step record, which is the window the step-first check refused.
            journal.OperationJournal.open(journal_path, workflow="first-run-v2", fingerprint="digest")
            with (
                mock.patch.object(setup, "STATE_PATH", state_path),
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
            ):
                setup.finish_interrupted_setup_journal(report)
            finished = json.loads(journal_path.read_text(encoding="utf-8"))
            self.assertEqual(finished["status"], "complete")
            self.assertEqual(finished["steps"]["final-state"]["status"], "complete")
            self.assertEqual(finished["result"], report)

    def test_manual_recovery_journal_is_not_completed_from_state(self):
        report = {"schemaVersion": 2, "status": "complete", "planDigest": "digest"}
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            state_path = root / "state.json"
            journal_path = root / "journal.json"
            state_path.write_text(json.dumps(report), encoding="utf-8")
            opened = journal.OperationJournal.open(journal_path, workflow="first-run-v2", fingerprint="digest")
            opened.fail("storage probe failed", manual_recovery=True)
            with (
                mock.patch.object(setup, "STATE_PATH", state_path),
                mock.patch.object(setup, "JOURNAL_PATH", journal_path),
            ):
                with self.assertRaisesRegex(setup.SetupError, "manual recovery"):
                    setup.finish_interrupted_setup_journal(report)
            self.assertEqual(json.loads(journal_path.read_text(encoding="utf-8"))["status"], "manual-recovery-required")

    def test_cancelled_journal_remains_reusable(self):
        self.check(journal={"schemaVersion": 1, "workflow": "first-run-v2", "status": "cancelled"}, should_block=False)

    def test_crash_between_final_state_write_and_journal_complete_fails_closed(self):
        self.check(
            state={"schemaVersion": 2, "status": "complete"},
            journal={"schemaVersion": 1, "workflow": "first-run-v2", "status": "resuming"},
            should_block=True,
        )

    def test_earlier_incomplete_setup_remains_resumable(self):
        self.check(journal={"schemaVersion": 1, "workflow": "first-run-v2", "status": "resuming"}, should_block=False)
        self.check(should_block=False)

    def test_existing_state_with_missing_unknown_or_nonstring_status_fails_closed(self):
        for state in (
            {"schemaVersion": 2},
            {"schemaVersion": 2, "status": []},
            {"schemaVersion": 2, "status": {}},
            {"schemaVersion": 2, "status": None},
            {"schemaVersion": 2, "status": 7},
            {"schemaVersion": 2, "status": "pending"},
            {"schemaVersion": 2, "status": "failed"},
        ):
            with self.subTest(state=state):
                self.check(state=state, should_block=True)

    def test_incomplete_journal_remains_resumable_when_state_is_absent(self):
        self.check(
            journal={"schemaVersion": 1, "workflow": "first-run-v2", "status": "pending"},
            should_block=False,
        )

    def test_corrupt_existing_state_cannot_authorize_database_recreation(self):
        self.check(corrupt_state=True, should_block=True)


if __name__ == "__main__":
    unittest.main()
