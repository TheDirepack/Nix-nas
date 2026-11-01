from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PASSING = "import unittest\nprint('rate limit exceeded')\nclass Fixture(unittest.TestCase):\n def test_ok(self): self.assertTrue(True)\n"
TIMED_OUT = "import time\nprint('owned-timeout-output', flush=True)\ntime.sleep(5)\n"


class UnitRunnerExitStatusTests(unittest.TestCase):
    def run_fixture(self, files: dict[str, str], *, jobs: int = 1) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "scripts/lib").mkdir(parents=True)
            (root / "tests").mkdir()
            shutil.copy2(ROOT / "scripts/run-unit-tests.py", root / "scripts/run-unit-tests.py")
            (root / "scripts/lib/manifest.py").write_text(
                "import pathlib, sys\npathlib.Path(sys.argv[sys.argv.index('--out') + 1]).write_text('fixture-manifest\\n')\n"
            )
            for name, content in files.items():
                (root / "tests" / name).write_text(content)
            env = {key: value for key, value in os.environ.items() if not key.startswith("NAS_")}
            env.update(
                TMPDIR=str(root),
                NAS_STATE_RUNTIME_ROOT=str(root / "runtime"),
                NAS_STATE_ROLLBACK_ROOT=str(root / "rollback"),
                NAS_STATE_RESTORE_JOURNAL=str(root / "rollback/restore.json"),
                NAS_SECRET_ROOT=str(root / "secrets"),
                NAS_SETUP_STATE=str(root / "setup/state.json"),
                NAS_SETUP_JOURNAL=str(root / "setup/journal.json"),
                NAS_SETUP_STATE_ROOT=str(root / "setup"),
                NAS_OPERATION_ROOT=str(root / "operations"),
                NAS_OPERATION_GROUP="users",
                NAS_IDENTITY_LOCK=str(root / "identity.lock"),
            )
            return subprocess.run(
                [
                    sys.executable,
                    str(root / "scripts/run-unit-tests.py"),
                    "--quiet",
                    "--pattern",
                    "test_fixture*.py",
                    "--timeout",
                    "1",
                    "--jobs",
                    str(jobs),
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

    def test_failure_text_cannot_turn_an_ordinary_failure_into_a_timeout(self) -> None:
        for message in ("rate limit exceeded", "deadline exceeded"):
            with self.subTest(message=message):
                result = self.run_fixture(
                    {
                        "test_fixture_failure.py": "import unittest\nclass Fixture(unittest.TestCase):\n def test_fail(self): self.fail("
                        + repr(message)
                        + ")\n"
                    }
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertIn("Unit test failure:", result.stderr)
                self.assertNotIn("Unit test timeout:", result.stderr)

    def test_ordinary_failure_without_timeout_words_keeps_exit_one(self) -> None:
        result = self.run_fixture(
            {
                "test_fixture_failure.py": "import unittest\nclass Fixture(unittest.TestCase):\n def test_fail(self): self.fail('ordinary failure')\n"
            }
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unit suite failed:", result.stderr)

    def test_zero_test_failure_is_not_a_timeout_even_when_output_says_exceeded(self) -> None:
        result = self.run_fixture({"test_fixture_empty.py": "print('rate limit exceeded')\n"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("0 ran across 1 files", result.stderr)

    def test_all_skipped_failure_is_not_a_timeout_even_when_output_says_exceeded(self) -> None:
        result = self.run_fixture(
            {
                "test_fixture_skipped.py": "import unittest\nprint('rate limit exceeded')\nclass Fixture(unittest.TestCase):\n @unittest.skip('fixture')\n def test_skipped(self): pass\n"
            }
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("all discovered tests were skipped", result.stderr)

    def test_real_timeout_keeps_exit_124_and_captured_output(self) -> None:
        result = self.run_fixture({"test_fixture_timeout.py": TIMED_OUT})
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertIn("owned-timeout-output", result.stderr)
        self.assertIn("Unit test timeout:", result.stderr)
        self.assertIn("exceeded 1s", result.stderr)

    def test_mixed_parallel_timeout_and_ordinary_failure_keeps_exit_124(self) -> None:
        result = self.run_fixture(
            {
                "test_fixture_failure.py": "import unittest\nclass Fixture(unittest.TestCase):\n def test_fail(self): self.fail('ordinary failure')\n",
                "test_fixture_timeout.py": TIMED_OUT,
            },
            jobs=2,
        )
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertIn("Unit test timeout:", result.stderr)
        self.assertIn("Unit test failure:", result.stderr)

    def test_success_output_with_timeout_words_keeps_exit_zero(self) -> None:
        result = self.run_fixture({"test_fixture_ok.py": PASSING})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unit suite passed: 1 tests", result.stdout)
        self.assertEqual(result.stderr, "")
