from __future__ import annotations

import pathlib
import subprocess
import sys
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ScriptInventoryTests(unittest.TestCase):
    def test_every_python_console_entrypoint_targets_a_real_module_and_main(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        sys.path.insert(0, str(ROOT / "services"))
        for name, target in data["project"]["scripts"].items():
            module_name, function = target.split(":", 1)
            with self.subTest(entrypoint=name):
                module = __import__(module_name)
                self.assertTrue(callable(getattr(module, function, None)))

    def test_safe_cli_help_surfaces_do_not_touch_system_state(self):
        commands = [
            [sys.executable, "services/nas_doctor.py", "--help"],
            [sys.executable, "services/nas_feature_control.py", "--help"],
            [sys.executable, "services/nas_identity_sync.py", "--help"],
            [sys.executable, "services/nas_migrate_state.py", "--help"],
            [sys.executable, "services/nas_setup.py", "--help"],
            [sys.executable, "services/nas_state.py", "--help"],
            ["bash", "scripts/package-release.sh", "--help"],
            ["bash", "scripts/qemu-test.sh", "--help"],
            ["bash", "scripts/update-nas.sh", "--help"],
            ["bash", "scripts/vm-bundles.sh", "--help"],
        ]
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("usage", (result.stdout + result.stderr).lower())

    def test_every_shell_script_is_parseable_and_has_strict_mode_when_executable_workflow(self):
        for path in sorted((ROOT / "scripts").rglob("*.sh")):
            with self.subTest(path=path.name):
                result = subprocess.run(["bash", "-n", str(path)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                text = path.read_text(encoding="utf-8")
                if path.parent.name != "lib":
                    self.assertRegex(text[:300], r"set -E?euo pipefail|set -Eeuo pipefail")


if __name__ == "__main__":
    unittest.main()
