from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_check_report",
    ROOT / "scripts" / "ci-check-report.py",
)
assert SPEC and SPEC.loader
ci_check_report = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ci_check_report
SPEC.loader.exec_module(ci_check_report)


class CiCheckReportTests(unittest.TestCase):
    def test_parse_and_render_preserve_all_sections(self) -> None:
        checks = ci_check_report.parse_checks(
            ["static=success", "unit=failure", "coverage=skipped"]
        )
        summary = ci_check_report.render_summary("Pre-build qualification", checks)
        self.assertIn("static", summary)
        self.assertIn("unit", summary)
        self.assertIn("coverage", summary)
        self.assertEqual(
            [check.name for check in ci_check_report.failed_checks(checks)],
            ["unit"],
        )

    def test_cancelled_and_failure_are_both_fatal(self) -> None:
        checks = ci_check_report.parse_checks(
            ["one=success", "two=cancelled", "three=failure"]
        )
        self.assertEqual(
            [check.outcome for check in ci_check_report.failed_checks(checks)],
            ["cancelled", "failure"],
        )

    def test_invalid_outcome_argument_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ci_check_report.parse_checks(["missing-separator"])
        with self.assertRaises(ValueError):
            ci_check_report.parse_checks([])


if __name__ == "__main__":
    unittest.main()
