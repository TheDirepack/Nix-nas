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

    def test_crash_between_final_state_write_and_journal_complete_fails_closed(self):
        self.check(
            state={"schemaVersion": 2, "status": "complete"},
            journal={"schemaVersion": 1, "workflow": "first-run-v2", "status": "resuming"},
            should_block=True,
        )

    def test_earlier_incomplete_setup_remains_resumable(self):
        self.check(journal={"schemaVersion": 1, "workflow": "first-run-v2", "status": "resuming"}, should_block=False)
        self.check(should_block=False)

    def test_corrupt_existing_state_cannot_authorize_database_recreation(self):
        self.check(corrupt_state=True, should_block=True)


if __name__ == "__main__":
    unittest.main()
