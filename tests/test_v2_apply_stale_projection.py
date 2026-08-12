from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_apply as apply_v2  # noqa: E402
from nas_v2_systemd import SystemdProjectionError  # noqa: E402


class V2ApplyStaleProjectionTests(unittest.TestCase):
    def test_stale_projection_file_is_removed_transactionally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "systemd"
            descriptors = root / "descriptors"
            descriptors.mkdir(parents=True)
            stale = descriptors / "removed.session.json"
            stale.write_text('{"serviceId":"removed"}\n', encoding="utf-8")
            current = root / "manifest.json"

            stale_paths = apply_v2._projection_stale_files(root, {current})
            changed = apply_v2._replace_bundle(
                [(current, b'{"schemaVersion":1}\n', 0o644)],
                remove_paths=stale_paths,
            )

            self.assertFalse(stale.exists())
            self.assertTrue(current.exists())
            self.assertIn(stale, changed)
            self.assertIn(current, changed)

    def test_failed_bundle_restores_replaced_and_deleted_projection_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "systemd"
            root.mkdir(parents=True)
            current = root / "manifest.json"
            stale = root / "descriptors" / "removed.session.json"
            stale.parent.mkdir()
            current.write_text("old-manifest\n", encoding="utf-8")
            stale.write_text("old-descriptor\n", encoding="utf-8")

            original_fsync = apply_v2._fsync_directory
            calls = 0

            def fail_once(directory: pathlib.Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError("simulated fsync failure")
                original_fsync(directory)

            with (
                mock.patch.object(apply_v2, "_fsync_directory", side_effect=fail_once),
                self.assertRaisesRegex(OSError, "simulated fsync failure"),
            ):
                apply_v2._replace_bundle(
                    [(current, b"new-manifest\n", 0o644)],
                    remove_paths={stale},
                )

            self.assertEqual(current.read_text(encoding="utf-8"), "old-manifest\n")
            self.assertEqual(stale.read_text(encoding="utf-8"), "old-descriptor\n")

    def test_projection_root_rejects_unexpected_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "systemd"
            root.mkdir(parents=True)
            outside = pathlib.Path(tmp) / "outside"
            outside.write_text("outside\n", encoding="utf-8")
            (root / "unexpected").symlink_to(outside)

            with self.assertRaisesRegex(SystemdProjectionError, "non-regular entry"):
                apply_v2._projection_stale_files(root, set())


if __name__ == "__main__":
    unittest.main()
