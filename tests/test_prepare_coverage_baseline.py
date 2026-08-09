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

    def test_corrects_only_known_stale_main_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_fixture(
                root,
                "tests/test_alpha20_cockpit.py",
                'keep\n        self.assertIn("qemu-evidence", workflow)\n'
                '        self.assertIn("installer-evidence", workflow)\n',
            )
            self.write_fixture(
                root,
                "tests/test_managed_service.py",
                '"exposure": {"type": "dns", "value": "app.nas.local"}\n',
            )
            self.write_fixture(
                root,
                "tests/test_service_caddy_validate.py",
                '"exposure": {"type": "path", "value": "/api"}\n',
            )

            self.assertEqual(baseline.prepare(root), 4)
            combined = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("test_*.py"))
            self.assertNotIn("qemu-evidence", combined)
            self.assertNotIn("installer-evidence", combined)
            self.assertIn("app.service.local", combined)
            self.assertIn("/managed-api", combined)

    def test_rejects_ambiguous_duplicate_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for relative, stale, _replacement in baseline.FIXES:
                self.write_fixture(root, relative, stale)
            path = root / "tests/test_managed_service.py"
            path.write_text(path.read_text(encoding="utf-8") * 2, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "expected at most one stale fixture"):
                baseline.prepare(root)

    def test_rejects_a_partially_corrected_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for relative, stale, replacement in baseline.FIXES:
                self.write_fixture(root, relative, replacement or "fixture already removed\n")
            relative, stale, _replacement = baseline.FIXES[-1]
            self.write_fixture(root, relative, stale)

            with self.assertRaisesRegex(ValueError, "partially corrected"):
                baseline.prepare(root)

    def test_cli_reports_invalid_root_without_a_traceback(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["prepare-coverage-baseline.py", "x" * 300]):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(baseline.main(), 2)
        self.assertIn("prepare-coverage-baseline:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
