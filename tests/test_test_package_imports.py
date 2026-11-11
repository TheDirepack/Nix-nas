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
            outside = pathlib.Path(raw) / "outside"
            outside.mkdir()
            for cwd, import_path in ((ROOT, raw), (outside, os.pathsep.join((str(ROOT), raw)))):
                with self.subTest(cwd=cwd):
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            "from tests import test_secret_security; print(test_secret_security.__file__)",
                        ],
                        cwd=cwd,
                        env={**os.environ, "PYTHONPATH": import_path},
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(pathlib.Path(result.stdout.strip()), ROOT / "tests/test_secret_security.py")

    def test_namespace_package_is_shadowed_even_from_its_repository_directory(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            repository = root / "repository"
            (repository / "tests").mkdir(parents=True)
            (repository / "tests/probe.py").write_text("value = 'repository'\n")
            installed = root / "installed/tests"
            installed.mkdir(parents=True)
            (installed / "__init__.py").write_text("raise RuntimeError('competing regular tests package imported')\n")
            result = subprocess.run(
                [sys.executable, "-c", "from tests import probe"],
                cwd=repository,
                env={**os.environ, "PYTHONPATH": str(installed.parent)},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("competing regular tests package imported", result.stderr)


if __name__ == "__main__":
    unittest.main()
