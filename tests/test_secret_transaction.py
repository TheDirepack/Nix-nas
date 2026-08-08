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
                      stop) [[ "${NAS_TX_STOP_FAIL:-0}" != 1 ]] ;;
                      start) [[ "${NAS_TX_START_FAIL:-0}" != 1 ]] ;;
                      *) exit 0 ;;
                    esac
                    """
                ),
                encoding="utf-8",
            )
            systemctl.chmod(0o755)

            real_mv = subprocess.run(["sh", "-c", "command -v mv"], check=True, capture_output=True, text=True).stdout.strip()
            mv = work / "bin/mv"
            mv.write_text(
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env bash
                    count=0
                    [[ ! -f "$NAS_TX_MV_COUNT" ]] || count=$(cat "$NAS_TX_MV_COUNT")
                    count=$((count + 1))
                    printf '%s' "$count" > "$NAS_TX_MV_COUNT"
                    if [[ "${{NAS_TX_MV_FAIL_AT:-0}}" == "$count" ]]; then
                      exit 74
                    fi
                    exec {real_mv} "$@"
                    """
                ),
                encoding="utf-8",
            )
            mv.chmod(0o755)

            script = textwrap.dedent(
                f"""\
                set -Eeuo pipefail
                export PATH={work / 'bin'}:$PATH
                export NAS_SECRET_TX_PRIVILEGE=""
                export NAS_SECRET_TX_SYSTEMCTL={systemctl!s}
                export NAS_TX_LOG={work / 'systemctl.log'!s}
                export NAS_TX_MV_COUNT={work / 'mv.count'!s}
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
        self.assert_ok(result)
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
        self.assert_ok(result)

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
        self.assert_ok(result)

    def test_commit_keeps_staged_tree(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            nas_secret_tx_commit
            [[ -f root/new && ! -e root/old && ! -e previous ]]
            [[ "$NAS_SECRET_TX_PHASE" == committed ]]
            """
        )
        self.assert_ok(result)

    def test_commit_before_swap_and_double_commit_are_rejected(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            ! nas_secret_tx_commit
            [[ -f root/old && -f stage/new ]]
            nas_secret_tx_swap
            nas_secret_tx_commit
            ! nas_secret_tx_commit
            [[ -f root/new && ! -e previous ]]
            """
        )
        self.assert_ok(result)

    def test_double_swap_is_rejected_without_destroying_new_tree(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            ! nas_secret_tx_swap
            [[ -f root/new && -f previous/old ]]
            set +e
            nas_secret_tx_cleanup 79
            rc=$?
            set -e
            [[ $rc -eq 79 && -f root/old && ! -e root/new ]]
            """
        )
        self.assert_ok(result)

    def test_missing_previous_tree_is_manual_recovery_not_false_success(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            rm -rf previous
            set +e
            nas_secret_tx_cleanup 80
            rc=$?
            set -e
            [[ $rc -eq 125 ]]
            [[ ! -e root/new ]]
            ! grep -q '^start nas-protected-services.target$' systemctl.log
            """
        )
        self.assert_ok(result)

    def test_missing_ready_marker_prevents_restart_and_reports_manual_recovery(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            rm -f previous/ready
            set +e
            nas_secret_tx_cleanup 81
            rc=$?
            set -e
            [[ $rc -eq 125 && -f root/old ]]
            ! grep -q '^start nas-protected-services.target$' systemctl.log
            """
        )
        self.assert_ok(result)

    def test_symlinked_stage_is_rejected_before_service_stop(self) -> None:
        result = self.run_scenario(
            """
            mkdir outside
            touch outside/new outside/ready
            rm -rf stage
            ln -s outside stage
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            ! nas_secret_tx_swap
            [[ -f root/old && -f outside/new ]]
            [[ ! -s systemctl.log ]]
            """
        )
        self.assert_ok(result)

    def test_symlinked_live_root_is_rejected_before_service_stop(self) -> None:
        result = self.run_scenario(
            """
            mkdir outside
            touch outside/old outside/ready
            rm -rf root
            ln -s outside root
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            ! nas_secret_tx_swap
            [[ -f outside/old && -f stage/new ]]
            [[ ! -s systemctl.log ]]
            """
        )
        self.assert_ok(result)

    def test_preexisting_previous_tree_is_rejected_before_service_stop(self) -> None:
        result = self.run_scenario(
            """
            mkdir previous
            touch previous/stale
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            ! nas_secret_tx_swap
            [[ -f root/old && -f stage/new && -f previous/stale ]]
            [[ ! -s systemctl.log ]]
            """
        )
        self.assert_ok(result)

    def test_missing_stage_is_rejected_before_service_stop(self) -> None:
        result = self.run_scenario(
            """
            rm -rf stage
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            ! nas_secret_tx_swap
            [[ -f root/old ]]
            [[ ! -s systemctl.log ]]
            """
        )
        self.assert_ok(result)

    def test_absolute_disjoint_paths_are_required(self) -> None:
        result = self.run_scenario(
            """
            ! nas_secret_tx_init root "$PWD/stage" "$PWD/previous"
            ! nas_secret_tx_init "$PWD/root" "$PWD/root/child" "$PWD/previous"
            ! nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/stage/previous"
            ! nas_secret_tx_init / "$PWD/stage" "$PWD/previous"
            [[ -f root/old && -f stage/new ]]
            """
        )
        self.assert_ok(result)

    def test_transaction_directory_must_own_stage_and_previous_but_not_live_root(self) -> None:
        result = self.run_scenario(
            """
            mkdir -p tx/new
            cp stage/new stage/ready tx/new/
            rm -rf stage
            ! nas_secret_tx_init "$PWD/root" "$PWD/tx/new" "$PWD/tx/previous" nas-protected-services.target "$PWD/root/tx"
            nas_secret_tx_init "$PWD/root" "$PWD/tx/new" "$PWD/tx/previous" nas-protected-services.target "$PWD/tx"
            nas_secret_tx_swap
            nas_secret_tx_commit
            [[ -f root/new && ! -e tx ]]
            """
        )
        self.assert_ok(result)

    def test_invalid_or_option_like_systemd_targets_are_rejected(self) -> None:
        result = self.run_scenario(
            """
            ! nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous" '--root=/tmp.target'
            ! nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous" 'bad.service'
            ! nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous" $'bad.target\\nnext'
            [[ ! -s systemctl.log ]]
            """
        )
        self.assert_ok(result)

    def test_cleanup_rejects_non_exit_status_values(self) -> None:
        result = self.run_scenario(
            """
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            set +e
            nas_secret_tx_cleanup nope
            rc1=$?
            nas_secret_tx_cleanup 256
            rc2=$?
            set -e
            [[ $rc1 -eq 125 && $rc2 -eq 125 ]]
            [[ -f root/old && -f stage/new ]]
            """
        )
        self.assert_ok(result)

    def test_inactive_system_without_prior_root_rolls_back_to_no_root(self) -> None:
        result = self.run_scenario(
            """
            export NAS_TX_ACTIVE=0
            rm -rf root
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            nas_secret_tx_swap
            [[ -f root/new ]]
            set +e
            nas_secret_tx_cleanup 82
            rc=$?
            set -e
            [[ $rc -eq 82 && ! -e root && ! -e previous ]]
            ! grep -q '^start ' systemctl.log
            """
        )
        self.assert_ok(result)

    def test_stop_failure_can_be_cleaned_up_without_filesystem_swap(self) -> None:
        result = self.run_scenario(
            """
            export NAS_TX_STOP_FAIL=1
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            set +e
            nas_secret_tx_swap
            swap_rc=$?
            nas_secret_tx_cleanup 83
            cleanup_rc=$?
            set -e
            [[ $swap_rc -ne 0 && $cleanup_rc -eq 125 ]]
            [[ -f root/old ]]
            """
        )
        # Rollback also cannot stop the target in this injected failure state, so 125 is correct.
        self.assert_ok(result)

    def test_first_move_failure_does_not_claim_successful_rollback(self) -> None:
        result = self.run_scenario(
            """
            export NAS_TX_MV_FAIL_AT=1
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            set +e
            nas_secret_tx_swap
            swap_rc=$?
            nas_secret_tx_cleanup 84
            cleanup_rc=$?
            set -e
            [[ $swap_rc -ne 0 && $cleanup_rc -eq 84 ]]
            [[ -f root/old && ! -e previous ]]
            grep -q '^start nas-protected-services.target$' systemctl.log
            """
        )
        self.assert_ok(result)

    def test_second_move_failure_restores_previous_tree(self) -> None:
        result = self.run_scenario(
            """
            export NAS_TX_MV_FAIL_AT=2
            nas_secret_tx_init "$PWD/root" "$PWD/stage" "$PWD/previous"
            set +e
            nas_secret_tx_swap
            swap_rc=$?
            nas_secret_tx_cleanup 85
            cleanup_rc=$?
            set -e
            [[ $swap_rc -ne 0 && $cleanup_rc -eq 85 ]]
            [[ -f root/old && ! -e root/new && ! -e previous ]]
            grep -q '^start nas-protected-services.target$' systemctl.log
            """
        )
        self.assert_ok(result)


if __name__ == "__main__":
    unittest.main()
