from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "security-static-scan.py"
spec = importlib.util.spec_from_file_location("nas_security_static_scan_command_forms", SCRIPT)
assert spec is not None and spec.loader is not None
scanner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = scanner
spec.loader.exec_module(scanner)

SCAN_PATHS = (
    ("sh", scanner.scan_shell, "shell-eval"),
    ("nix", scanner.scan_nix, "generated-shell-eval"),
)

EXECUTED_EVAL_FORMS = (
    'eval "$payload"',
    'builtin eval "$payload"',
    'builtin -- eval "$payload"',
    'command eval "$payload"',
    'command -- eval "$payload"',
    'command -p eval "$payload"',
    'command -p -p eval "$payload"',
    'command builtin eval "$payload"',
    'command -- builtin eval "$payload"',
    'builtin -- command eval "$payload"',
    'IFS=: command -p eval "$payload"',
    'PAYLOAD=x command eval "$payload"',
    '! command -p eval "$payload"',
    '! command -- eval "$payload"',
    'if builtin -- eval "$payload"; then',
    'while eval "$payload"; do :; done',
    'time eval "$payload"',
    # A command substitution executes inside a double-quoted word, so the
    # substitution body is scanned rather than blanked as literal text.
    'result="$(eval "$user_command")"',
    'result="$(command eval "$user_command")"',
    'result="$(command -- eval "$user_command")"',
    'result="`eval "$user_command"`"',
    'echo "$(eval "$user_command")"',
    'result="$(cd "$(dirname "$0")" && eval "$user_command")"',
)

NOT_EXECUTED_EVAL_FORMS = (
    # The first -- ends option parsing, so command runs a program named --.
    'command -- -- eval "$payload"',
    # After --, -p is the command name rather than an option.
    'command -- -p eval "$payload"',
    # -v/-V only describe the command.
    'command -v eval "$payload"',
    'command -V eval "$payload"',
    'command -pv eval "$payload"',
    # Quoted text is data, not an executed command.
    """printf '%s\\n' 'Use (command eval "$value") with care'""",
    '''printf "%s\\n" "Use (command eval \\"$value\\") with care"''',
    # Quoting the substitution itself keeps eval as text.
    """printf '%s\\n' 'result="$(eval "$value")"'""",
    # A command boundary inside a quoted word must not promote a later word.
    'echo "foo(" eval "$payload"',
    'echo "eval is a word"',
    'my_eval "$payload"',
    "nix eval --raw .#value",
)

TRACING_FORMS = (
    "set -x",
    "set -x;",
    "set -e -x",
    "set -euxo pipefail",
    "set -o xtrace",
    "set -e -o xtrace",
    "set -o pipefail -x",
    "bash -x ./helper.sh",
    "bash -e -x",
    "bash -o xtrace",
    "sh -o xtrace",
    "bash --norc -o xtrace script.sh",
    "{ set -x; }",
)

NON_TRACING_FORMS = (
    "set -euo pipefail",
    "set +x",
    "set +o xtrace",
    "set -- -x",
    'bash -c "set -x"',
    """printf '%s\\n' 'set -x'""",
    "bash -e script.sh",
)


def scan_line(text: str, suffix: str, scan) -> set[str]:
    with tempfile.TemporaryDirectory() as raw:
        path = pathlib.Path(raw) / f"sample.{suffix}"
        path.write_text(f"{text}\n", encoding="utf-8")
        return {finding.rule for finding in scan(path)}


class StaticScanCommandFormsTests(unittest.TestCase):
    def test_eval_form_predicate_matches_executed_wrappers(self) -> None:
        for line in EXECUTED_EVAL_FORMS:
            with self.subTest(line=line):
                self.assertTrue(scanner.shell_eval_in_command_position(line))

    def test_eval_form_predicate_rejects_non_executed_forms(self) -> None:
        for line in NOT_EXECUTED_EVAL_FORMS:
            with self.subTest(line=line):
                self.assertFalse(scanner.shell_eval_in_command_position(line))

    def test_shell_and_nix_scans_report_executed_eval_forms(self) -> None:
        for line in EXECUTED_EVAL_FORMS:
            for suffix, scan, rule in SCAN_PATHS:
                with self.subTest(line=line, scan=suffix):
                    self.assertIn(rule, scan_line(line, suffix, scan))

    def test_shell_and_nix_scans_ignore_non_executed_eval_forms(self) -> None:
        for line in NOT_EXECUTED_EVAL_FORMS:
            for suffix, scan, rule in SCAN_PATHS:
                with self.subTest(line=line, scan=suffix):
                    self.assertNotIn(rule, scan_line(line, suffix, scan))

    def test_xtrace_predicate_matches_tracing_forms(self) -> None:
        for line in TRACING_FORMS:
            with self.subTest(line=line):
                self.assertTrue(scanner.shell_xtrace_enabled(line))

    def test_xtrace_predicate_rejects_disabled_and_quoted_forms(self) -> None:
        for line in NON_TRACING_FORMS:
            with self.subTest(line=line):
                self.assertFalse(scanner.shell_xtrace_enabled(line))

    def test_shell_and_nix_scans_report_tracing_forms(self) -> None:
        for line in TRACING_FORMS:
            for suffix, scan, rule in (
                ("sh", scanner.scan_shell, "shell-xtrace-secret-leak"),
                ("nix", scanner.scan_nix, "generated-shell-xtrace-secret-leak"),
            ):
                with self.subTest(line=line, scan=suffix):
                    self.assertIn(rule, scan_line(line, suffix, scan))

    def test_shell_and_nix_scans_ignore_disabled_and_quoted_tracing(self) -> None:
        for line in NON_TRACING_FORMS:
            for suffix, scan, rule in (
                ("sh", scanner.scan_shell, "shell-xtrace-secret-leak"),
                ("nix", scanner.scan_nix, "generated-shell-xtrace-secret-leak"),
            ):
                with self.subTest(line=line, scan=suffix):
                    self.assertNotIn(rule, scan_line(line, suffix, scan))


if __name__ == "__main__":
    unittest.main()
