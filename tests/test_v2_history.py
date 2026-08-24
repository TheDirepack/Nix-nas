from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

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
