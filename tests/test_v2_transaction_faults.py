from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_history as history  # noqa: E402


STAGES = (
    "after-nmstate",
    "after-firewalld",
    "after-systemd",
    "after-caddy",
    "before-mark-applied",
    "after-mark-applied",
)


class V2TransactionFaultTests(unittest.TestCase):
    def _run_case(self, *, established: bool, failure_stage: str) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = root / "services.yaml"
            repository = root / "history.git"
            authority.write_text("schemaVersion: 3\nservices: {}\n", encoding="utf-8")
            baseline = history.ensure_bootstrap_applied(authority=authority, repository=repository)["applied"]

            if established:
                authority.write_text("schemaVersion: 3\nservices:\n  old: {}\n", encoding="utf-8")
                old = history.record_desired(authority=authority, repository=repository)["head"]
                history.mark_applied(authority=authority, repository=repository, commit=old)
                history.clear_previous_applied(authority=authority, repository=repository)
                rollback_revision = old
                rollback_document = "schemaVersion: 3\nservices:\n  old: {}\n"
            else:
                rollback_revision = baseline
                rollback_document = "schemaVersion: 3\nservices: {}\n"

            authority.write_text("schemaVersion: 3\nservices:\n  new: {}\n", encoding="utf-8")
            failed = history.record_desired(authority=authority, repository=repository)["head"]

            native = {"nmstate": "new", "firewalld": "new", "systemd": "new", "caddy": "new"}
            if failure_stage == "after-mark-applied":
                history.mark_applied(authority=authority, repository=repository, commit=failed)

            restored = history.restore_applied(
                authority=authority,
                repository=repository,
                failed_commit=failed,
            )
            self.assertTrue(restored["changed"])
            self.assertEqual(restored["restoredFrom"], rollback_revision)

            # A restarted finite reconciliation projects the restored authority
            # into every native subsystem before advancing applied again.
            authority.write_text(rollback_document, encoding="utf-8")
            native = {name: "old" if established else "baseline" for name in native}
            repaired = history.record_desired(authority=authority, repository=repository)
            history.mark_applied(authority=authority, repository=repository, commit=repaired["head"])
            history.clear_previous_applied(authority=authority, repository=repository)

            status = history.history_status(authority=authority, repository=repository)
            self.assertTrue(status["inSync"])
            self.assertEqual(authority.read_text(encoding="utf-8"), rollback_document)
            self.assertEqual(set(native.values()), {"old" if established else "baseline"})
            self.assertIsNone(history._rev_parse(repository, authority, "git", history.PREVIOUS_APPLIED_REF))

    def test_first_boot_fault_matrix_converges_to_the_empty_baseline(self) -> None:
        for stage in STAGES:
            with self.subTest(stage=stage):
                self._run_case(established=False, failure_stage=stage)

    def test_established_fault_matrix_converges_to_the_last_good_revision(self) -> None:
        for stage in STAGES:
            with self.subTest(stage=stage):
                self._run_case(established=True, failure_stage=stage)


if __name__ == "__main__":
    unittest.main()
