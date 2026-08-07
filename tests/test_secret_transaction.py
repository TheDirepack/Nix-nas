from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "scripts/lib/nas-secret-transaction.sh"


class SecretTransactionShellTests(unittest.TestCase):
    def run_scenario(self, body: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory)
            (work / "bin").mkdir()
            (work / "root").mkdir()
            (work / "stage").mkdir()
            for path in (work / "root/ready", work / "root/old", work / "stage/ready", work / "stage/new"):
                path.touch()
            systemctl = work / "bin/systemctl"
            systemctl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    printf '%s\\n' "$*" >> "$NAS_TX_LOG"
                    case "$1" in
                      is-active) [[ "${NAS_TX_ACTIVE:-1}" == 1 ]] ;;
                      start) [[ "${NAS_TX_START_FAIL:-0}" != 1 ]] ;;
                      *) exit 0 ;;
                    esac
                    """
                ),
                encoding="utf-8",
            )
            systemctl.chmod(0o755)
            script = textwrap.dedent(
                f"""\
                set -Eeuo pipefail
                export NAS_SECRET_TX_PRIVILEGE=""
                export NAS_SECRET_TX_SYSTEMCTL={systemctl!s}
                export NAS_TX_LOG={work / "systemctl.log"!s}
                source {LIBRARY!s}
                {body}
                """
            )
            return subprocess.run(
                ["bash", "-c", script],
                cwd=work,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )

    def test_rollback_restores_previous_tree_without_sudo(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            set +e
            nas_secret_tx_cleanup 71
            rc=$?
            set -e
            [[ $rc -eq 71 ]]
            [[ -f root/old && ! -e root/new ]]
            grep -q '^start nas-protected-services.target$' systemctl.log
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("sudo", result.stderr)

    def test_pre_swap_failure_does_not_touch_active_target(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            set +e
            nas_secret_tx_cleanup 77
            rc=$?
            set -e
            [[ $rc -eq 77 ]]
            [[ -f root/old && -f root/ready ]]
            [[ ! -s systemctl.log ]]
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_restart_reports_incomplete_rollback(self) -> None:
        result = self.run_scenario(
            """
            export NAS_TX_START_FAIL=1
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            set +e
            nas_secret_tx_cleanup 78
            rc=$?
            set -e
            [[ $rc -eq 125 ]]
            [[ -f root/old && ! -e root/new ]]
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_commit_keeps_staged_tree(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            nas_secret_tx_commit
            [[ -f root/new && ! -e root/old && ! -e previous ]]
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
