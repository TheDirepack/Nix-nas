from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CliSurfaceTests(unittest.TestCase):
    def run_python(self, name: str, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        merged["PYTHONPATH"] = str(ROOT / "services")
        if env:
            merged.update(env)
        return subprocess.run(
            [sys.executable, str(ROOT / "services" / f"{name}.py"), *args],
            cwd=ROOT,
            env=merged,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_all_argument_driven_python_commands_have_working_help(self) -> None:
        commands = (
            "nas_cockpit_api",
            "nas_doctor",
            "nas_v2_control",
            "nas_identity_sync",
            "nas_setup",
            "nas_state",
        )
        for command in commands:
            with self.subTest(command=command):
                result = self.run_python(command, "--help")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout.lower())
                self.assertNotIn("Traceback", result.stderr)

    def test_unknown_cli_commands_fail_without_tracebacks(self) -> None:
        for command in (
            "nas_doctor",
            "nas_v2_control",
            "nas_identity_sync",
            "nas_setup",
            "nas_state",
        ):
            with self.subTest(command=command):
                result = self.run_python(command, "definitely-not-a-command")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)

    def test_alert_router_invalid_listen_configuration_fails_before_serving(self) -> None:
        for listen in ("invalid", "127.0.0.1:not-a-port", "127.0.0.1:0", "127.0.0.1:65536", ":9093"):
            with self.subTest(listen=listen):
                result = self.run_python("nas_alert_router", env={"NAS_ALERT_ROUTER_LISTEN": listen})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid NAS_ALERT_ROUTER_LISTEN", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_python_cli_parsers_reject_hostile_unknown_arguments_without_execution(self) -> None:
        commands = (
            "nas_cockpit_api",
            "nas_doctor",
            "nas_v2_control",
            "nas_identity_sync",
            "nas_setup",
            "nas_state",
        )
        payload = "--fuzz-;$(touch /tmp/nas-cli-pwned);../../../etc/shadow;<script>alert(1)</script>;' OR 1=1 --"
        marker = pathlib.Path("/tmp/nas-cli-pwned")
        marker.unlink(missing_ok=True)
        for command in commands:
            with self.subTest(command=command):
                result = self.run_python(command, payload)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(marker.exists())

    def test_package_release_rejects_missing_output_directory(self) -> None:
        result = subprocess.run(
            [str(ROOT / "scripts" / "package-release.sh")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stderr)

    def test_qemu_wrapper_rejects_unknown_mode_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [str(ROOT / "scripts" / "qemu-test.sh"), "not-a-mode"],
                cwd=ROOT,
                env={**os.environ, "NAS_QEMU_CACHE_DIR": tmp},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown mode", result.stderr)
            self.assertEqual(list(pathlib.Path(tmp).iterdir()), [])

    def test_update_wrapper_help_is_non_mutating(self) -> None:
        result = subprocess.run(
            [str(ROOT / "scripts" / "update-nas.sh"), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Usage: nas-update", result.stdout)


if __name__ == "__main__":
    unittest.main()
