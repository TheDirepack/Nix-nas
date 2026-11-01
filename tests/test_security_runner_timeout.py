from __future__ import annotations

import importlib.util
import io
import pathlib
import signal
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]


class SecurityRunnerTimeoutTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "security_timeout_fixture", ROOT / "scripts/run-security-tests.py"
        )
        assert spec is not None and spec.loader is not None
        self.runner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.runner
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(self.runner)
        self.check = self.runner.Check("fixture-check", ("fixture-command",))

    def main(self, outcome) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        run = mock.Mock(side_effect=outcome) if isinstance(outcome, Exception) else mock.Mock(return_value=outcome)
        with (
            mock.patch.object(sys, "argv", ["run-security-tests.py"]),
            mock.patch.object(self.runner, "CHECKS", (self.check,)),
            mock.patch.object(self.runner, "run", run),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = self.runner.main()
        run.assert_called_once_with(self.check.command, timeout=180)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_timeout_retains_both_bounded_output_tails(self) -> None:
        error = subprocess.TimeoutExpired(
            self.check.command,
            180,
            output="discard-stdout-" + "x" * 16000 + "stdout-tail",
            stderr="discard-stderr-" + "y" * 16000 + "stderr-tail",
        )
        status, stdout, stderr = self.main(error)
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("timed out: fixture-check after 180s", stderr)
        self.assertIn("stdout-tail", stderr)
        self.assertIn("stderr-tail", stderr)
        self.assertNotIn("discard-stdout-", stderr)
        self.assertNotIn("discard-stderr-", stderr)
        self.assertLess(len(stderr), 32200)

    def test_timeout_accepts_byte_streams_without_printing_bytes_repr(self) -> None:
        status, _stdout, stderr = self.main(
            subprocess.TimeoutExpired(self.check.command, 180, output=b"byte-output\xff", stderr=b"byte-error")
        )
        self.assertEqual(status, 1)
        self.assertIn("byte-output\ufffd", stderr)
        self.assertIn("byte-error", stderr)
        self.assertNotIn("b'", stderr)

    def test_timeout_with_no_captured_output_still_fails(self) -> None:
        status, stdout, stderr = self.main(subprocess.TimeoutExpired(self.check.command, 180))
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("timed out", stderr)

    def test_nonzero_exit_keeps_the_existing_output_policy(self) -> None:
        status, stdout, stderr = self.main(
            subprocess.CompletedProcess(self.check.command, 9, "stdout-tail", "stderr-tail")
        )
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("security check failed: fixture-check", stderr)
        self.assertIn("stdout-tail", stderr)
        self.assertIn("stderr-tail", stderr)

    def test_success_still_reports_the_check_without_failure_output(self) -> None:
        status, stdout, stderr = self.main(subprocess.CompletedProcess(self.check.command, 0, "fixture-output", ""))
        self.assertEqual(status, 0)
        self.assertIn("security check ok: fixture-check", stdout)
        self.assertIn("security tier ok: 1 checks", stdout)
        self.assertEqual(stderr, "")

    def test_timeout_still_kills_and_collects_the_owned_process_group(self) -> None:
        process = mock.Mock(pid=987654)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(self.check.command, 180),
            ("collected-out", "collected-err"),
        ]
        with (
            mock.patch.object(self.runner.subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(self.runner.os, "killpg") as killpg,
        ):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                self.runner.run(self.check.command, timeout=180)
        popen.assert_called_once()
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        killpg.assert_called_once_with(process.pid, signal.SIGKILL)
        self.assertEqual(process.communicate.call_args_list, [mock.call(timeout=180), mock.call()])
        self.assertEqual(caught.exception.stdout, "collected-out")
        self.assertEqual(caught.exception.stderr, "collected-err")
