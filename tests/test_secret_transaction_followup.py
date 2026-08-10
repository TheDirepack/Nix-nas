from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "scripts/lib/nas-secret-transaction.sh"


class SecretTransactionFollowupTests(unittest.TestCase):
    def run_scenario(self, body: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory)
            (work / "bin").mkdir()
            (work / "root").mkdir()
            (work / "stage").mkdir()
            for path in (
                work / "root/ready",
                work / "root/old",
                work / "stage/ready",
                work / "stage/new",
            ):
                path.touch()

            systemctl = work / "bin/systemctl"
            systemctl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    printf '%s\\n' "$*" >> "$NAS_TX_LOG"
                    case "$1" in
                      is-active) [[ "${NAS_TX_ACTIVE:-1}" == 1 ]] ;;
                      stop) [[ "${NAS_TX_STOP_FAIL:-0}" != 1 ]] ;;
                      start) [[ "${NAS_TX_START_FAIL:-0}" != 1 ]] ;;
                      *) exit 0 ;;
                    esac
                    """
                ),
                encoding="utf-8",
            )
            systemctl.chmod(0o755)

            real_mv = subprocess.run(
                ["sh", "-c", "command -v mv"], check=True, capture_output=True, text=True
            ).stdout.strip()
            mv = work / "bin/mv"
            mv.write_text(
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env bash
                    count=0
                    [[ ! -f "$NAS_TX_MV_COUNT" ]] || count=$(cat "$NAS_TX_MV_COUNT")
                    count=$((count + 1))
                    printf '%s' "$count" > "$NAS_TX_MV_COUNT"
                    {real_mv} "$@" || exit $?
                    if [[ "${{NAS_TX_MV_TAMPER_READY_AT:-0}}" == "$count" ]]; then
                      destination="${{@: -1}}"
                      rm -f -- "$destination/ready"
                      ln -s /dev/null "$destination/ready"
                    fi
                    """
                ),
                encoding="utf-8",
            )
            mv.chmod(0o755)

            real_rm = subprocess.run(
                ["sh", "-c", "command -v rm"], check=True, capture_output=True, text=True
            ).stdout.strip()
            rm = work / "bin/rm"
            rm.write_text(
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env bash
                    if [[ -n "${{NAS_TX_RM_FAIL_MATCH:-}}" && "$*" == *"${{NAS_TX_RM_FAIL_MATCH}}"* ]]; then
                      exit 75
                    fi
                    exec {real_rm} "$@"
                    """
                ),
                encoding="utf-8",
            )
            rm.chmod(0o755)

            script = textwrap.dedent(
                f"""\
                set -Eeuo pipefail
                export PATH={work / "bin"}:$PATH
                export NAS_SECRET_TX_PRIVILEGE=""
                export NAS_SECRET_TX_SYSTEMCTL={systemctl!s}
                export NAS_TX_LOG={work / "systemctl.log"!s}
                export NAS_TX_MV_COUNT={work / "mv.count"!s}
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
                timeout=20,
            )

    def assert_ok(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_stage_ready_marker_is_required_before_service_stop(self) -> None:
        for setup in (
            "rm -f stage/ready",
            "rm -f stage/ready; ln -s /dev/null stage/ready",
        ):
            with self.subTest(setup=setup):
                result = self.run_scenario(
                    f"""
                    {setup}
                    nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
                    ! nas_secret_tx_swap
                    [[ -f root/old && -f stage/new && ! -s systemctl.log ]]
                    """
                )
                self.assert_ok(result)

    def test_zero_status_cleanup_without_commit_rolls_back_and_fails_closed(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            set +e; nas_secret_tx_cleanup 0; rc=$?; set -e
            [[ $rc -eq 125 ]]
            [[ -f root/old && -f root/ready && ! -e root/new && ! -e previous ]]
            grep -q '^start nas-protected-services.target$' systemctl.log
            """
        )
        self.assert_ok(result)

    def test_commit_cleanup_failure_keeps_new_tree_authoritative(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            export NAS_TX_RM_FAIL_MATCH=previous
            set +e; nas_secret_tx_commit; commit_rc=$?; set -e
            unset NAS_TX_RM_FAIL_MATCH
            [[ $commit_rc -eq 125 ]]
            [[ "$NAS_SECRET_TX_COMMITTED" == true ]]
            [[ "$NAS_SECRET_TX_PHASE" == commit-cleanup-failed ]]
            [[ -f root/new && -f root/ready && -f previous/old ]]
            ! nas_secret_tx_rollback
            set +e; nas_secret_tx_cleanup 125; cleanup_rc=$?; set -e
            [[ $cleanup_rc -eq 125 && -f root/new && -f previous/old ]]
            """
        )
        self.assert_ok(result)

    def test_post_move_ready_substitution_is_detected_and_old_tree_is_restored(self) -> None:
        result = self.run_scenario(
            """
            export NAS_TX_MV_TAMPER_READY_AT=2
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            set +e
            nas_secret_tx_swap; swap_rc=$?
            nas_secret_tx_cleanup 86; cleanup_rc=$?
            set -e
            [[ $swap_rc -ne 0 && $cleanup_rc -eq 86 ]]
            [[ -f root/old && -f root/ready && ! -L root/ready && ! -e root/new ]]
            grep -q '^start nas-protected-services.target$' systemctl.log
            """
        )
        self.assert_ok(result)


if __name__ == "__main__":
    unittest.main()
