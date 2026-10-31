from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class CiCheckReportingTests(unittest.TestCase):
    def scenario(self, *, failure: int = 17, guarded: bool = False, tee_failure: bool = False) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            command = f'ci_run source fixture "Fixture check" bash -c "echo native-output; exit {failure}"'
            if guarded:
                command += ' || status=$?\nexit "${status:-0}"'
            script = "\n".join(
                [
                    "set -euo pipefail",
                    'source "$CI_HELPER"',
                    'tee() { command tee "$@"; return 29; }' if tee_failure else "",
                    command,
                ]
            )
            result = subprocess.run(
                ["bash", "-c", script],
                env={
                    **os.environ,
                    "CI_HELPER": str(ROOT / ".github/ci-checks.sh"),
                    "CI_LOG_DIR": str(root),
                    "CI_RESULTS_FILE": str(root / "results.tsv"),
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            rows = (root / "results.tsv").read_text() if (root / "results.tsv").exists() else ""
            self.assertIn("native-output", (root / "source-fixture.log").read_text())
            self.assertTrue(rows, "ci_run did not record a results row")
            return result.returncode, result.stdout, rows

    def test_failed_plain_call_records_native_failure_before_errexit(self) -> None:
        status, output, rows = self.scenario()
        self.assertEqual(status, 17)
        self.assertIn("::endgroup::", output)
        self.assertIn("::error title=Fixture check::exit 17", output)
        self.assertEqual(rows.split("\t")[3], "17")

    def test_guarded_call_keeps_native_failure(self) -> None:
        status, _, rows = self.scenario(guarded=True)
        self.assertEqual(status, 17)
        self.assertEqual(rows.split("\t")[3], "17")

    def test_log_writer_failure_is_not_reported_as_success(self) -> None:
        status, _, rows = self.scenario(failure=0, tee_failure=True)
        self.assertEqual(status, 29)
        self.assertEqual(rows.split("\t")[3], "29")

    def test_command_failure_takes_precedence_over_log_writer_failure(self) -> None:
        status, _, rows = self.scenario(failure=17, tee_failure=True)
        self.assertEqual(status, 17)
        self.assertEqual(rows.split("\t")[3], "17")

    def test_success_records_success(self) -> None:
        status, output, rows = self.scenario(failure=0)
        self.assertEqual(status, 0)
        self.assertNotIn("::error", output)
        self.assertEqual(rows.split("\t")[3], "0")
