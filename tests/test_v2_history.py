from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import io
import json
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_history as history  # noqa: E402


@unittest.skipUnless(shutil.which("git"), "git is required")
class V2HistoryTests(unittest.TestCase):
    def write_authority(self, root: pathlib.Path, value: str) -> pathlib.Path:
        authority = root / "services.yaml"
        authority.write_text(value, encoding="utf-8")
        return authority

    def test_record_tracks_only_authority_and_mark_applied(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = self.write_authority(root, "schemaVersion: 3\nservices: {}\n")
            (root / "unrelated.txt").write_text("must never be tracked\n", encoding="utf-8")
            repository = root / "history.git"

            first = history.record_desired(authority=authority, repository=repository)
            self.assertTrue(first["changed"])
            status = history.history_status(authority=authority, repository=repository)
            self.assertEqual(status["desired"], first["head"])
            self.assertIsNone(status["applied"])

            applied = history.mark_applied(authority=authority, repository=repository)
            self.assertEqual(applied["applied"], first["head"])
            status = history.history_status(authority=authority, repository=repository)
            self.assertTrue(status["inSync"])

            names = subprocess.check_output(
                [
                    "git",
                    f"--git-dir={repository}",
                    f"--work-tree={root}",
                    "ls-tree",
                    "-r",
                    "--name-only",
                    "HEAD",
                ],
                text=True,
            ).splitlines()
            self.assertEqual(names, ["services.yaml"])

    def test_noop_record_reuses_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = self.write_authority(root, "schemaVersion: 3\nservices: {}\n")
            repository = root / "history.git"
            first = history.record_desired(authority=authority, repository=repository)
            second = history.record_desired(authority=authority, repository=repository)
            self.assertFalse(second["changed"])
            self.assertEqual(second["head"], first["head"])

    def test_bootstrap_baseline_is_parent_of_first_desired_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = self.write_authority(
                root,
                "schemaVersion: 3\nservices:\n  demo:\n    name: Demo\n    workload: {kind: daemon}\n    runtime: {type: systemd, unit: demo.service}\n",
            )
            repository = root / "history.git"

            baseline = history.ensure_bootstrap_applied(authority=authority, repository=repository)
            desired = history.record_desired(authority=authority, repository=repository)

            self.assertTrue(baseline["created"])
            self.assertEqual(
                history.history_status(authority=authority, repository=repository)["applied"], baseline["applied"]
            )
            self.assertNotEqual(desired["head"], baseline["applied"])
            parent = subprocess.check_output(
                ["git", f"--git-dir={repository}", "rev-parse", f"{desired['head']}^"], text=True
            ).strip()
            self.assertEqual(parent, baseline["applied"])

            restored = history.restore_applied(
                authority=authority,
                repository=repository,
                failed_commit=desired["head"],
            )
            self.assertTrue(restored["changed"])
            self.assertEqual(authority.read_text(encoding="utf-8"), "schemaVersion: 3\nservices: {}\n")

    def test_bootstrap_refuses_an_existing_unapplied_history(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = self.write_authority(root, "schemaVersion: 3\nservices: {}\n")
            repository = root / "history.git"
            history.record_desired(authority=authority, repository=repository)
            with self.assertRaisesRegex(history.DesiredStateHistoryError, "no applied revision"):
                history.ensure_bootstrap_applied(authority=authority, repository=repository)

    def test_bootstrap_cli_creates_the_baseline_before_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = self.write_authority(
                root,
                "schemaVersion: 3\nservices:\n  demo: {}\n",
            )
            repository = root / "history.git"
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    history.main(
                        [
                            "--authority",
                            str(authority),
                            "--repository",
                            str(repository),
                            "bootstrap",
                        ]
                    ),
                    0,
                )
            self.assertTrue(json.loads(output.getvalue())["created"])
            self.assertIsNotNone(history.history_status(authority=authority, repository=repository)["applied"])

    def test_rollback_after_mark_applied_uses_the_previous_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = self.write_authority(root, "schemaVersion: 3\nservices: {}\n")
            repository = root / "history.git"
            baseline = history.ensure_bootstrap_applied(authority=authority, repository=repository)["applied"]
            authority.write_text(
                "schemaVersion: 3\nservices:\n  demo:\n    name: Demo\n    workload: {kind: daemon}\n    runtime: {type: systemd, unit: demo.service}\n",
                encoding="utf-8",
            )
            failed = history.record_desired(authority=authority, repository=repository)["head"]
            history.mark_applied(authority=authority, repository=repository, commit=failed)

            restored = history.restore_applied(
                authority=authority,
                repository=repository,
                failed_commit=failed,
            )

            status = history.history_status(authority=authority, repository=repository)
            self.assertTrue(restored["changed"])
            self.assertEqual(restored["restoredFrom"], baseline)
            self.assertEqual(status["applied"], baseline)
            self.assertIsNone(history._rev_parse(repository, authority, "git", history.PREVIOUS_APPLIED_REF))
            self.assertEqual(authority.read_text(encoding="utf-8"), "schemaVersion: 3\nservices: {}\n")

    def test_restore_applied_preserves_failed_attempt_in_history(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            original = "# Nix NAS desired state\nschemaVersion: 3\nservices: {}\n"
            authority = self.write_authority(root, original)
            repository = root / "history.git"
            good = history.record_desired(authority=authority, repository=repository)
            history.mark_applied(authority=authority, repository=repository)

            authority.write_text(
                "# Nix NAS desired state\nschemaVersion: 3\nservices:\n  broken: {}\n",
                encoding="utf-8",
            )
            failed = history.record_desired(
                authority=authority,
                repository=repository,
                message="Attempt broken configuration",
            )
            self.assertNotEqual(failed["head"], good["head"])

            restored = history.restore_applied(
                authority=authority,
                repository=repository,
                failed_commit=failed["head"],
            )
            self.assertTrue(restored["changed"])
            self.assertFalse(restored["superseded"])
            self.assertEqual(restored["restoredFrom"], good["head"])
            self.assertEqual(authority.read_text(encoding="utf-8"), original)
            self.assertNotEqual(restored["head"], failed["head"])

            log = subprocess.check_output(
                ["git", f"--git-dir={repository}", "log", "--format=%s", "-3", "HEAD"],
                text=True,
            ).splitlines()
            self.assertEqual(log[0], "Automatic rollback to last applied Managed Services V2 state")
            self.assertIn("Attempt broken configuration", log)

    def test_restore_does_not_overwrite_newer_uncompiled_edit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            original = "schemaVersion: 3\nservices: {}\n"
            authority = self.write_authority(root, original)
            repository = root / "history.git"
            history.record_desired(authority=authority, repository=repository)
            history.mark_applied(authority=authority, repository=repository)

            failed_text = "schemaVersion: 3\nservices:\n  failed: {}\n"
            authority.write_text(failed_text, encoding="utf-8")
            failed = history.record_desired(authority=authority, repository=repository)

            newer = "schemaVersion: 3\nservices:\n  newer: {}\n"
            authority.write_text(newer, encoding="utf-8")
            restored = history.restore_applied(
                authority=authority,
                repository=repository,
                failed_commit=failed["head"],
            )
            self.assertTrue(restored["superseded"])
            self.assertFalse(restored["changed"])
            self.assertIsNone(restored["restoredFrom"])
            self.assertEqual(authority.read_text(encoding="utf-8"), newer)

    def test_pending_marker_is_cleared_only_for_current_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = self.write_authority(root, "schemaVersion: 3\nservices: {}\n")
            repository = root / "history.git"
            current = history.record_desired(authority=authority, repository=repository)
            pending = root / "reconcile.pending"
            pending.touch()

            acknowledged = history.acknowledge_pending(
                authority=authority,
                repository=repository,
                commit=current["head"],
                pending=pending,
            )
            self.assertTrue(acknowledged["current"])
            self.assertFalse(pending.exists())

            pending.touch()
            authority.write_text("schemaVersion: 3\nservices:\n  newer: {}\n", encoding="utf-8")
            superseded = history.acknowledge_pending(
                authority=authority,
                repository=repository,
                commit=current["head"],
                pending=pending,
            )
            self.assertFalse(superseded["current"])
            self.assertTrue(pending.exists())

    def test_restore_requires_last_applied_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            authority = self.write_authority(root, "schemaVersion: 3\nservices: {}\n")
            repository = root / "history.git"
            history.record_desired(authority=authority, repository=repository)
            with self.assertRaisesRegex(history.DesiredStateHistoryError, "no last-applied"):
                history.restore_applied(authority=authority, repository=repository)


if __name__ == "__main__":
    unittest.main()
