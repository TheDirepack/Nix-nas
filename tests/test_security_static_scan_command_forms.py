from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "security-static-scan.py"
spec = importlib.util.spec_from_file_location("nas_security_static_scan_tests", SCRIPT)
assert spec is not None and spec.loader is not None
scanner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = scanner
spec.loader.exec_module(scanner)


class StaticScanCommandFormsTests(unittest.TestCase):
    def test_eval_in_command_position_with_builtin_and_command_options(self) -> None:
        for line in (
            'eval "$payload"',
            'builtin eval "$payload"',
            'builtin -- eval "$payload"',
            'command eval "$payload"',
            'command -- eval "$payload"',
            'command -p eval "$payload"',
            'if builtin -- eval "$payload"; then',
        ):
            with self.subTest(line=line):
                self.assertTrue(scanner.shell_eval_in_command_position(line))
        for line in ('echo "eval is a word"', 'my_eval "$payload"'):
            with self.subTest(line=line):
                self.assertFalse(scanner.shell_eval_in_command_position(line))

    def test_both_shell_and_embedded_nix_sinks_reject_builtin_dashdash_eval(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            for suffix, func, rule in (
                ("sh", scanner.scan_shell, "shell-eval"),
                ("nix", scanner.scan_nix, "generated-shell-eval"),
            ):
                path = root / f"unsafe.{suffix}"
                path.write_text('  builtin -- eval "$payload"\n', encoding="utf-8")
                with self.subTest(suffix=suffix):
                    self.assertIn(rule, {finding.rule for finding in func(path)})


if __name__ == "__main__":
    unittest.main()
