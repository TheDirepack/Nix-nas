from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-coverage.py"
spec = importlib.util.spec_from_file_location("coverage_gate", CHECKER)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class CoverageGateTests(unittest.TestCase):
    def run_gate(self, summary, *, baseline_summary=None):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            report = root / "coverage.json"

            def write(path, value):
                path.write_text(
                    json.dumps({"files": {name: {"summary": value} for name in gate.FLOORS}, "totals": value})
                )

            write(report, summary)
            args = [sys.executable, str(CHECKER), str(report)]
            if baseline_summary is not None:
                baseline = root / "baseline.json"
                write(baseline, baseline_summary)
                args.extend(["--baseline", str(baseline)])
            return subprocess.run(args, capture_output=True, text=True, timeout=10)

    def test_zero_branches_cannot_be_hidden_by_covered_statements(self):
        result = self.run_gate({"percent_covered": 99, "num_branches": 100, "covered_branches": 0})
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_invalid_branch_metrics_fail_closed(self):
        for value in (
            {"percent_covered": "nan"},
            {"num_branches": 0},
            {"num_branches": 10, "covered_branches": 11},
            {"num_branches": 10, "covered_branches": "nan"},
            {"num_branches": True, "covered_branches": 1},
        ):
            with self.subTest(value=value):
                self.assertNotEqual(self.run_gate(value).returncode, 0)

    def test_actual_branch_drift_is_enforced(self):
        result = self.run_gate(
            {"percent_covered": 100, "num_branches": 100, "covered_branches": 90},
            baseline_summary={"percent_covered": 100, "num_branches": 100, "covered_branches": 100},
        )
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_every_custom_service_has_an_explicit_floor(self):
        self.assertEqual(set(gate.FLOORS), {p.relative_to(ROOT).as_posix() for p in (ROOT / "services").glob("*.py")})

    def test_complete_branch_report_passes(self):
        self.assertEqual(
            self.run_gate({"percent_covered": 100, "num_branches": 100, "covered_branches": 100}).returncode, 0
        )


if __name__ == "__main__":
    unittest.main()
