from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestPackageImports(unittest.TestCase):
    def test_repository_tests_win_over_an_installed_regular_package(self):
        with tempfile.TemporaryDirectory() as raw:
            installed = pathlib.Path(raw) / "tests"
            installed.mkdir()
            (installed / "__init__.py").write_text("raise RuntimeError('unrelated tests package imported')\n")
            result = subprocess.run(
                [sys.executable, "-c", "from tests import test_secret_security; print(test_secret_security.__file__)"],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": raw},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(pathlib.Path(result.stdout.strip()), ROOT / "tests/test_secret_security.py")


if __name__ == "__main__":
    unittest.main()
