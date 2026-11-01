from __future__ import annotations

import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class CiCheckReportingTests(unittest.TestCase):
    def scenario(
        self,
        *,
        failure: int = 17,
        guarded: bool = False,
        child_guarded: bool = False,
        tee_failure: bool = False,
        results_failure: bool = False,
    ) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            results = root / "results.tsv"
            if results_failure:
                results.mkdir()
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
            if child_guarded:
                script = f'bash -euo pipefail -c {shlex.quote(script)} || status=$?\nexit "${{status:-0}}"'
            result = subprocess.run(
                ["bash", "-c", script],
                env={
                    **os.environ,
                    "CI_HELPER": str(ROOT / ".github/ci-checks.sh"),
                    "CI_LOG_DIR": str(root),
                    "CI_RESULTS_FILE": str(results),
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            rows = results.read_text() if results.is_file() else ""
            self.assertIn("native-output", (root / "source-fixture.log").read_text())
            if results_failure:
                self.assertFalse(rows)
            else:
                self.assertTrue(rows, "ci_run did not record a results row")
            return result.returncode, result.stdout + result.stderr, rows

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

    def test_guarded_child_shell_keeps_errexit_and_records_native_failure(self) -> None:
        status, output, rows = self.scenario(child_guarded=True)
        self.assertEqual(status, 17)
        self.assertIn("::endgroup::", output)
        self.assertIn("::error title=Fixture check::exit 17", output)
        self.assertEqual(rows.split("\t")[3], "17")

    def test_results_append_failure_is_fatal_for_plain_guarded_and_child_callers(self) -> None:
        for guarded, child_guarded in ((False, False), (True, False), (False, True)):
            for failure, tee_failure in ((0, False), (17, False), (0, True), (17, True)):
                with self.subTest(
                    guarded=guarded, child_guarded=child_guarded, failure=failure, tee_failure=tee_failure
                ):
                    status, output, _ = self.scenario(
                        failure=failure,
                        guarded=guarded,
                        child_guarded=child_guarded,
                        tee_failure=tee_failure,
                        results_failure=True,
                    )
                    self.assertEqual(status, failure or (29 if tee_failure else 1))
                    self.assertIn("::endgroup::", output)
                    self.assertIn("unable to append results", output)
                    self.assertIn(f"::error title=Fixture check::exit {status}", output)

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
