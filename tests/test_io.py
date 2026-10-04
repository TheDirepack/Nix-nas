from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

import nas_common


class IoPrimitiveTests(unittest.TestCase):
    def test_fsync_directory_opens_directory_and_closes_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw)
            with mock.patch.object(nas_common.os, "fsync") as fsync:
                nas_common.fsync_directory(path)
            fsync.assert_called_once()

    def test_callers_keep_patchable_local_aliases(self) -> None:
        import nas_v2_bootstrap as bootstrap
        import nas_v2_generation as generation
        import nas_v2_apply as apply
        import nas_v2_systemd_reconcile as reconcile
        import nas_operation_journal as journal

        self.assertIs(bootstrap._fsync_directory, nas_common.fsync_directory)
        self.assertIs(generation._fsync_directory, nas_common.fsync_directory)
        self.assertIs(apply._fsync_directory, nas_common.fsync_directory)
        self.assertIs(reconcile._fsync_directory, nas_common.fsync_directory)
        self.assertIs(journal.fsync_directory, nas_common.fsync_directory)

    def test_bundle_rollback_syncs_removal_of_newly_created_files(self) -> None:
        import nas_v2_apply as apply

        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            first, second = root / "first", root / "second"
            replace = apply.os.replace

            def fail_second(source, target):
                if target == second:
                    raise OSError("replace failed")
                replace(source, target)

            with (
                mock.patch.object(apply.os, "replace", side_effect=fail_second),
                mock.patch.object(apply, "_fsync_directory") as synced,
            ):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    apply._replace_bundle([(first, b"one", 0o640), (second, b"two", 0o640)])
                synced.assert_called_once_with(root)
            self.assertFalse(first.exists())
            self.assertFalse(second.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_no_duplicate_io_module_is_packaged(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[1]
        self.assertFalse((root / "services/nas_io.py").exists())
        self.assertNotIn('"nas_io"', (root / "pyproject.toml").read_text())

    def test_descriptor_is_closed_when_sync_fails(self) -> None:
        with (
            mock.patch.object(nas_common.os, "open", return_value=42) as opened,
            mock.patch.object(nas_common.os, "fsync", side_effect=OSError("sync failed")),
            mock.patch.object(nas_common.os, "close") as closed,
        ):
            with self.assertRaisesRegex(OSError, "sync failed"):
                nas_common.fsync_directory(pathlib.Path("/directory"))
        opened.assert_called_once_with(pathlib.Path("/directory"), nas_common.os.O_RDONLY | nas_common.os.O_DIRECTORY)
        closed.assert_called_once_with(42)


if __name__ == "__main__":
    unittest.main()
