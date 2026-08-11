from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

from tests.test_secret_security import ROOT, rendered_shell_helpers


class KeePassFailClosedTests(unittest.TestCase):
    def run_helper(
        self,
        command: str,
        *,
        listing: str = "",
        ls_status: int = 0,
        mkdir_status: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        helpers = rendered_shell_helpers(
            "kp_args",
            "entry_path",
            "ensure_group",
            "has_secret",
            "store_value",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = pathlib.Path(temp_dir)
            fake = temp / "keepassxc-cli"
            log = temp / "commands.log"
            fake.write_text(
                """#!/usr/bin/env bash
set -eu
cmd="$1"
shift
printf '%s\n' "$cmd" >> "$FAKE_KP_LOG"
case "$cmd" in
  ls)
    status="${FAKE_KP_LS_STATUS:-0}"
    if [[ "$status" -ne 0 ]]; then exit "$status"; fi
    printf '%b' "${FAKE_KP_LISTING:-}"
    ;;
  mkdir) exit "${FAKE_KP_MKDIR_STATUS:-0}" ;;
  add|edit|show|rm) exit 0 ;;
  *) exit 0 ;;
esac
""",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{temp}:{os.environ.get('PATH', '')}",
                "FAKE_KP_LOG": str(log),
                "FAKE_KP_LISTING": listing,
                "FAKE_KP_LS_STATUS": str(ls_status),
                "FAKE_KP_MKDIR_STATUS": str(mkdir_status),
            }
            script = (
                "set -Eeuo pipefail\n"
                "key_file=''\n"
                "database=/tmp/test.kdbx\n"
                "secret_group=NAS\n"
                "keepass_password=test-password\n" + helpers + command
            )
            result = subprocess.run(
                ["bash", "-c", script],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            return result, log.read_text(encoding="utf-8") if log.exists() else ""

    def test_argument_builder_succeeds_without_optional_key_file(self) -> None:
        result, _ = self.run_helper("kp_args\nprintf 'ok\\n'\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ok\n")

    def test_membership_uses_exact_flattened_listing(self) -> None:
        result, log = self.run_helper(
            "has_secret alpha\nif has_secret alp; then exit 9; fi\n",
            listing="alpha\nalphabet\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.splitlines(), ["ls", "ls"])

    def test_listing_failure_aborts_before_add_or_edit(self) -> None:
        result, log = self.run_helper("store_value alpha replacement\n", ls_status=7)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to inspect the KeePassXC secret group.", result.stderr)
        self.assertEqual(log.splitlines(), ["ls"])

    def test_group_creation_failure_is_not_ignored(self) -> None:
        result, log = self.run_helper("ensure_group\n", ls_status=1, mkdir_status=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to ensure KeePassXC group", result.stderr)
        self.assertEqual(log.splitlines(), ["ls", "mkdir"])


if __name__ == "__main__":
    unittest.main()
