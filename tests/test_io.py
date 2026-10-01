from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

import nas_io


class IoPrimitiveTests(unittest.TestCase):
    def test_fsync_directory_opens_directory_and_closes_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw)
            with mock.patch.object(nas_io.os, "fsync") as fsync:
                nas_io.fsync_directory(path)
            fsync.assert_called_once()

    def test_callers_keep_patchable_local_aliases(self) -> None:
        import nas_v2_bootstrap as bootstrap
        import nas_v2_generation as generation

        self.assertIs(bootstrap._fsync_directory, nas_io.fsync_directory)
        self.assertIs(generation._fsync_directory, nas_io.fsync_directory)


if __name__ == "__main__":
    unittest.main()
