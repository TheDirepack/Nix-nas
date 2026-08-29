from __future__ import annotations

import importlib.util
import json
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "nas_operation_journal_test", ROOT / "services" / "nas_operation_journal.py"
)
assert SPEC and SPEC.loader
journal_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = journal_module
SPEC.loader.exec_module(journal_module)


class OperationJournalTests(unittest.TestCase):
    def test_atomic_write_sets_mode_and_replaces_complete_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "nested" / "journal.json"
            journal_module.atomic_write_json(path, {"value": 1}, mode=0o640)
            self.assertEqual({"value": 1}, json.loads(path.read_text()))
            self.assertEqual(0o640, stat.S_IMODE(path.stat().st_mode))
            journal_module.atomic_write_json(path, {"value": 2}, mode=0o600)
            self.assertEqual({"value": 2}, json.loads(path.read_text()))
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual([], list(path.parent.glob(f".{path.name}.*")))

    def test_atomic_write_removes_temporary_file_after_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "journal.json"
            with mock.patch.object(journal_module.os, "replace", side_effect=OSError("fail")):
                with self.assertRaisesRegex(OSError, "fail"):
                    journal_module.atomic_write_json(path, {"value": 1})
            self.assertFalse(path.exists())
            self.assertEqual([], list(path.parent.glob(f".{path.name}.*")))

    def test_load_json_distinguishes_missing_invalid_and_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "journal.json"
            self.assertIsNone(journal_module.load_json(path))
            path.write_text("not-json")
            with self.assertRaisesRegex(journal_module.JournalError, "Invalid operation journal"):
                journal_module.load_json(path)
            path.write_text("[]")
            with self.assertRaisesRegex(journal_module.JournalError, "not a JSON object"):
                journal_module.load_json(path)

    def test_open_resume_and_terminal_state_semantics(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(journal_module.time, "time", return_value=10),
        ):
            path = pathlib.Path(temporary) / "journal.json"
            first = journal_module.OperationJournal.open(
                path, workflow="setup", fingerprint="same", metadata={"one": 1}
            )
            self.assertEqual("pending", first.value["status"])
            first.value["status"] = "failed"
            first.save()
            resumed = journal_module.OperationJournal.open(path, workflow="setup", fingerprint="same")
            self.assertEqual("resuming", resumed.value["status"])
            resumed.value["status"] = "complete"
            resumed.save()
            replacement = journal_module.OperationJournal.open(path, workflow="setup", fingerprint="new")
            self.assertEqual("pending", replacement.value["status"])
            self.assertEqual("new", replacement.value["fingerprint"])

    def test_open_rejects_wrong_workflow_fingerprint_and_manual_recovery(self) -> None:
        cases = [
            ({"schemaVersion": 2, "workflow": "setup", "fingerprint": "a", "status": "failed"}, "reconciliation"),
            ({"schemaVersion": 1, "workflow": "other", "fingerprint": "a", "status": "failed"}, "reconciliation"),
            ({"schemaVersion": 1, "workflow": "setup", "fingerprint": "other", "status": "failed"}, "different setup"),
            (
                {"schemaVersion": 1, "workflow": "setup", "fingerprint": "a", "status": "manual-recovery-required"},
                "explicit recovery",
            ),
        ]
        for value, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                path = pathlib.Path(temporary) / "journal.json"
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(journal_module.JournalError, expected):
                    journal_module.OperationJournal.open(path, workflow="setup", fingerprint="a")

    def test_manual_recovery_acknowledgement_is_strict_and_durable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "journal.json"
            with self.assertRaisesRegex(journal_module.JournalError, "No operation journal"):
                journal_module.OperationJournal.acknowledge_manual_recovery(path, workflow="setup", note="fixed")
            path.write_text(json.dumps({"schemaVersion": 1, "workflow": "other", "status": "manual-recovery-required"}))
            with self.assertRaisesRegex(journal_module.JournalError, "does not belong"):
                journal_module.OperationJournal.acknowledge_manual_recovery(path, workflow="setup", note="fixed")
            path.write_text(json.dumps({"schemaVersion": 1, "workflow": "setup", "status": "failed"}))
            with self.assertRaisesRegex(journal_module.JournalError, "not awaiting"):
                journal_module.OperationJournal.acknowledge_manual_recovery(path, workflow="setup", note="fixed")
            path.write_text(json.dumps({"schemaVersion": 1, "workflow": "setup", "status": "manual-recovery-required"}))
            result = journal_module.OperationJournal.acknowledge_manual_recovery(
                path, workflow="setup", note="verified storage"
            )
            self.assertEqual("reconciled", result.value["status"])
            self.assertEqual("verified storage", result.value["recoveryNote"])

    def test_verified_step_recovery_requires_exact_transaction_and_failed_step(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "journal.json"
            value = {
                "schemaVersion": 1,
                "workflow": "setup",
                "fingerprint": "same",
                "status": "manual-recovery-required",
                "currentStep": "storage",
                "steps": {"storage": {"status": "failed", "error": "mount check failed"}},
            }
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(journal_module.JournalError, "different setup"):
                journal_module.OperationJournal.complete_verified_recovery_step(
                    path,
                    workflow="setup",
                    fingerprint="different",
                    step="storage",
                    result={"pool": "tank"},
                )
            with self.assertRaisesRegex(journal_module.JournalError, "not awaiting.*identity"):
                journal_module.OperationJournal.complete_verified_recovery_step(
                    path,
                    workflow="setup",
                    fingerprint="same",
                    step="identity",
                    result={"ok": True},
                )
            recovered = journal_module.OperationJournal.complete_verified_recovery_step(
                path,
                workflow="setup",
                fingerprint="same",
                step="storage",
                result={"pool": "tank"},
                replacement_fingerprint="current",
            )
            self.assertEqual("reconciled", recovered.value["status"])
            self.assertIsNone(recovered.value["currentStep"])
            self.assertTrue(recovered.step_complete("storage"))
            self.assertEqual({"pool": "tank"}, recovered.result("storage"))
            self.assertEqual("current", recovered.value["fingerprint"])
            self.assertNotIn("error", recovered.value["steps"]["storage"])

    def test_step_and_workflow_lifecycle_clears_stale_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "journal.json"
            journal = journal_module.OperationJournal.open(path, workflow="setup", fingerprint="a")
            journal.value["steps"]["storage"] = {"error": "old"}
            journal.start_step("storage")
            self.assertEqual("running", journal.value["status"])
            self.assertNotIn("error", journal.value["steps"]["storage"])
            journal.fail_step("storage", "unsafe", manual_recovery=True)
            self.assertEqual("manual-recovery-required", journal.value["status"])
            self.assertFalse(journal.step_complete("storage"))
            journal.start_step("storage")
            journal.complete_step("storage", {"pool": "tank"})
            self.assertTrue(journal.step_complete("storage"))
            self.assertEqual({"pool": "tank"}, journal.result("storage"))
            self.assertIsNone(journal.result("missing"))
            journal.fail("later", manual_recovery=False)
            self.assertEqual("failed", journal.value["status"])
            journal.complete({"ok": True})
            self.assertEqual("complete", journal.value["status"])
            self.assertEqual({"ok": True}, journal.value["result"])


if __name__ == "__main__":
    unittest.main()
