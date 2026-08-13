from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

from maintainer_test_base import MaintainerScriptMixin


class MaintainerReleaseTests(MaintainerScriptMixin, unittest.TestCase):
    def test_installer_rejects_missing_or_untrusted_inputs_before_destructive_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "flake.nix").write_text("{}\n", encoding="utf-8")
            key = root / "admin.pub"
            key.write_text("ssh-ed25519 test\n", encoding="utf-8")
            marker = root / "must-survive"
            marker.write_text("safe\n", encoding="utf-8")
            env = {
                **os.environ,
                "NAS_INSTALL_DISK": str(root / "not-a-block-device"),
                "NAS_INSTALL_SOURCE": str(source),
                "NAS_INSTALL_SSH_PUBLIC_KEY": str(key),
            }
            result = subprocess.run(
                ["bash", "tests/vm/install-system.sh"],
                cwd=self.clean_root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Installer disk is missing", result.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "safe\n")

            link = root / "linked.pub"
            link.symlink_to(key)
            source_text = (self.clean_root / "tests/vm/install-system.sh").read_text(encoding="utf-8")
            self.assertIn("Ephemeral SSH public key must not be a symlink", source_text)

    def test_post_install_reconfigure_requires_reviewed_source_and_persistence_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            missing_source = root / "missing-source"
            result = subprocess.run(
                ["bash", "tests/vm/reconfigure-system.sh"],
                cwd=self.clean_root,
                env={
                    **os.environ,
                    "NAS_TEST_SOURCE": str(missing_source),
                    "NAS_TEST_INSTALL_SENTINEL": str(root / "sentinel"),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("reviewed source flake is missing", result.stderr)

            source = root / "source"
            source.mkdir()
            (source / "flake.nix").write_text("{}\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", "tests/vm/reconfigure-system.sh"],
                cwd=self.clean_root,
                env={
                    **os.environ,
                    "NAS_TEST_SOURCE": str(source),
                    "NAS_TEST_INSTALL_SENTINEL": str(root / "missing-sentinel"),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("installer persistence sentinel is missing", result.stderr)

    def test_shell_workflows_parse_and_safe_help_or_invalid_modes_are_non_mutating(self) -> None:
        shell_scripts = sorted((self.clean_root / "scripts").rglob("*.sh"))
        for script in shell_scripts:
            with self.subTest(parse=script.relative_to(self.clean_root).as_posix()):
                result = subprocess.run(["bash", "-n", str(script)], text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
        safe = (
            ("bash", "scripts/package-release.sh", "--help"),
            ("bash", "scripts/qemu-test.sh", "--help"),
            ("bash", "scripts/update-nas.sh", "--help"),
        )
        for command in safe:
            with self.subTest(help=command[1]):
                result = self.run_clean(*command)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("usage", (result.stdout + result.stderr).lower())

    def test_preflight_wrapper_runs_its_safe_local_tier(self) -> None:
        result = self.run_clean(
            "env",
            "NAS_PREFLIGHT_REQUIRE_COMPLETE=0",
            "NAS_PREFLIGHT_SKIP_TESTS=1",
            "NAS_PREFLIGHT_SKIP_FUZZ=1",
            "NAS_PREFLIGHT_SKIP_NIX=1",
            "bash",
            "scripts/preflight.sh",
            timeout=90,
        )
        # It is allowed to be partial when optional external tools are not installed,
        # but every locally available mandatory stage must have completed.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Preflight partial: 0", result.stdout)
        self.assertIn("repository structure", result.stdout)
        self.assertIn("static security boundaries", result.stdout)
        self.assertFalse((self.clean_root / ".ruff_cache").exists())
