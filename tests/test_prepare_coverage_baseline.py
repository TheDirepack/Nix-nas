from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "prepare_coverage_baseline", ROOT / "scripts/prepare-coverage-baseline.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load prepare-coverage-baseline.py")
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


class PrepareCoverageBaselineTests(unittest.TestCase):
    def write_fixture(self, root: pathlib.Path, relative: str, content: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_prepare_is_noop_when_fixture_is_already_corrected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_fixture(
                root,
                "scripts/run-unit-tests.py",
                baseline.RUNNER_EXCLUSION_REPLACEMENT,
            )
            self.assertEqual(baseline.prepare(root), 0)
            self.assertEqual(
                (root / "scripts/run-unit-tests.py").read_text(encoding="utf-8"),
                baseline.RUNNER_EXCLUSION_REPLACEMENT,
            )

    def test_prepare_aligns_main_fast_coverage_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_fixture(
                root,
                "scripts/run-unit-tests.py",
                baseline.RUNNER_EXCLUSION_STALE,
            )
            self.assertEqual(baseline.prepare(root), 1)
            rendered = (root / "scripts/run-unit-tests.py").read_text(encoding="utf-8")
            self.assertEqual(rendered, baseline.RUNNER_EXCLUSION_REPLACEMENT)
            self.assertIn('excluded.add("test_fuzz_custom_inputs.py")', rendered)

    def test_cli_applies_fix_without_traceback(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_fixture(
                root,
                "scripts/run-unit-tests.py",
                baseline.RUNNER_EXCLUSION_STALE,
            )
            with mock.patch.object(sys, "argv", ["prepare-coverage-baseline.py", tmp]):
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(baseline.main(), 0)
            self.assertEqual(
                (root / "scripts/run-unit-tests.py").read_text(encoding="utf-8"),
                baseline.RUNNER_EXCLUSION_REPLACEMENT,
            )
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_reports_invalid_root_without_a_traceback(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["prepare-coverage-baseline.py", "x" * 300]):
            with contextlib.redirect_stderr(stderr):
                result = baseline.main()
        self.assertEqual(result, 2)
        self.assertIn("prepare-coverage-baseline:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
