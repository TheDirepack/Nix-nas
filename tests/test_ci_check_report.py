from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
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
        checks = ci_check_report.parse_checks(["static=success", "unit=failure", "coverage=skipped"])
        summary = ci_check_report.render_summary("Pre-build qualification", checks)
        self.assertIn("static", summary)
        self.assertIn("unit", summary)
        self.assertIn("coverage", summary)
        self.assertEqual(
            [check.name for check in ci_check_report.failed_checks(checks)],
            ["unit"],
        )

    def test_detailed_results_include_command_timing_and_failure_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            failed_log = root / "static-ruff.log"
            failed_log.write_text("line one\nuseful failure\n", encoding="utf-8")
            results_path = root / "results.tsv"
            results_path.write_text(
                "static\truff\tPython lint\t1\t7\t"
                f"{failed_log}\truff check services tests scripts\n"
                "static\tpyright\tPython types\t0\t3\t"
                f"{root / 'static-pyright.log'}\tpyright --project pyproject.toml\n",
                encoding="utf-8",
            )

            results = ci_check_report.parse_results(results_path)
            summary = ci_check_report.render_summary(
                "Pre-build qualification",
                ci_check_report.parse_checks(["static=failure"]),
                results,
                tail_lines=10,
            )

        self.assertEqual(len(results), 2)
        self.assertEqual(
            [result.name for result in ci_check_report.failed_subchecks(results)],
            ["Python lint"],
        )
        self.assertIn("1 passed", summary)
        self.assertIn("1 failed", summary)
        self.assertIn("exit `1`", summary)
        self.assertIn("7s", summary)
        self.assertIn("ruff check services tests scripts", summary)
        self.assertIn("useful failure", summary)

    def test_missing_or_malformed_results_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(ValueError):
                ci_check_report.parse_results(root / "missing.tsv")

            malformed = root / "malformed.tsv"
            malformed.write_text("too\tfew\tfields\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                ci_check_report.parse_results(malformed)

    def test_cancelled_and_failure_are_both_fatal(self) -> None:
        checks = ci_check_report.parse_checks(["one=success", "two=cancelled", "three=failure"])
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
