from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_common as common


class SecretSubprocessRedactionTests(unittest.TestCase):
    def test_failed_child_cannot_reflect_protected_stdin_to_output(self) -> None:
        sentinel = "SUPER-SECRET-STDIN-SENTINEL"
        result = common.run_command(
            [
                sys.executable,
                "-c",
                (
                    "import sys; value=sys.stdin.read(); "
                    "print('stdout:' + value, end=''); "
                    "print('stderr:' + value, file=sys.stderr, end=''); "
                    "raise SystemExit(23)"
                ),
            ],
            input_text=sentinel,
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, 23)
        self.assertNotIn(sentinel, result.stdout)
        self.assertNotIn(sentinel, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("protected standard input", result.stderr)

    def test_successful_child_can_return_intentional_output_without_echoing_input(self) -> None:
        sentinel = "SUCCESS-SECRET-SENTINEL"
        result = common.run_command(
            [sys.executable, "-c", "import sys; sys.stdin.read(); print('intentional-result')"],
            input_text=sentinel,
            timeout_seconds=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "intentional-result")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(sentinel, result.stdout)

    def test_timeout_after_secret_input_does_not_return_partial_echo(self) -> None:
        sentinel = "TIMEOUT-SECRET-SENTINEL"
        result = common.run_command(
            [
                sys.executable,
                "-c",
                (
                    "import sys,time; value=sys.stdin.read(); "
                    "print(value, flush=True); print(value, file=sys.stderr, flush=True); time.sleep(5)"
                ),
            ],
            input_text=sentinel,
            timeout_seconds=0.1,
        )
        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(sentinel, result.stderr)
        self.assertIn("protected standard input", result.stderr)


if __name__ == "__main__":
    unittest.main()
