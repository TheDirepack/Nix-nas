"""Black-box tests of the Zig secret-activation transaction (zig/src/transaction.zig).

The harness binary drives the typestate API one command per line; PATH shims
for systemctl, mv, rm and a privilege wrapper inject the same faults the shell
library was tested against.
"""

from __future__ import annotations

import contextlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from collections.abc import Iterator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from zig_binaries import harness_bin_dir  # noqa: E402

TARGET = "nas-protected-services.target"

SYSTEMCTL = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    [[ ! -f "$NAS_TX_OVERRIDES" ]] || source "$NAS_TX_OVERRIDES"
    printf '%s\\n' "$*" >> "$NAS_TX_LOG"
    [[ "${NAS_TX_UNAVAILABLE:-0}" != 1 ]] || { echo 'Failed to connect to bus' >&2; exit 1; }
    case "$1" in
      show)
        [[ "${NAS_TX_SHOW_FAIL:-0}" != 1 ]] || { echo 'Failed to query status' >&2; exit 1; }
        printf 'LoadState=%s\\n' "${NAS_TX_LOAD_STATE:-loaded}"
        if [[ "${NAS_TX_JOB_MISSING:-0}" != 1 ]]; then
          printf 'Job=%s\\n' "${NAS_TX_JOB:-}"
        fi
        if [[ -n "${NAS_TX_STATE:-}" ]]; then
          printf 'ActiveState=%s\\n' "$NAS_TX_STATE"
        elif [[ "${NAS_TX_ACTIVE:-1}" == 1 && ! -e "$NAS_TX_INACTIVE_MARKER" ]]; then
          echo ActiveState=active
        else
          echo ActiveState=inactive
        fi
        ;;
      stop)
        if [[ -n "${NAS_TX_STOP_SETS:-}" ]]; then
          printf 'export %s\\n' "$NAS_TX_STOP_SETS" >> "$NAS_TX_OVERRIDES"
          exit "${NAS_TX_STOP_RC:-0}"
        fi
        if [[ "${NAS_TX_STOP_FAIL:-0}" == 1 ]]; then
          [[ "${NAS_TX_STOP_LEFT_INACTIVE:-0}" != 1 ]] || touch "$NAS_TX_INACTIVE_MARKER"
          exit 1
        fi
        touch "$NAS_TX_INACTIVE_MARKER"
        ;;
      start) [[ "${NAS_TX_START_FAIL:-0}" != 1 ]] ;;
      *) exit 0 ;;
    esac
    """
)

MV = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    count=0
    [[ ! -f "$NAS_TX_MV_COUNT" ]] || count=$(cat "$NAS_TX_MV_COUNT")
    count=$((count + 1))
    printf '%s' "$count" > "$NAS_TX_MV_COUNT"
    if [[ "${NAS_TX_MV_FAIL_AT:-0}" == "$count" ]]; then
      exit 74
    fi
    exec REAL_MV "$@"
    """
)

RM = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    if [[ -n "${NAS_TX_RM_FAIL_PATH:-}" && "${@: -1}" == "$NAS_TX_RM_FAIL_PATH" ]]; then
      exit 74
    fi
    exec REAL_RM "$@"
    """
)

PRIV = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    printf '%s\\n' "$*" >> "$NAS_TX_PRIV_LOG"
    if [[ "${NAS_TX_SIM_ELEVATE:-0}" != 1 ]]; then
      exit 66
    fi
    [[ "$1" != -- ]] || shift
    exec "$@"
    """
)


class Result:
    def __init__(self, completed: subprocess.CompletedProcess[str]) -> None:
        self.stdout = completed.stdout
        self.stderr = completed.stderr
        self.returncode = completed.returncode
        self.lines = [line.split(" ", 1) for line in completed.stdout.splitlines() if line]

    def status(self, verb: str, index: int = -1) -> int:
        values = [int(value) for name, value in self.lines if name == verb]
        return values[index]

    def value(self, verb: str) -> str:
        return [value for name, value in self.lines if name == verb][-1]


class Scenario:
    def __init__(self, work: pathlib.Path, env: dict[str, str]) -> None:
        self.work = work
        self.env = env

    def path(self, relative: str) -> pathlib.Path:
        return self.work / relative

    def p(self, relative: str) -> str:
        return str(self.work / relative)

    def run(self, *commands: str) -> Result:
        lines = [
            command if "\t" in command else command.replace(" ", "\t", 1 if command.startswith("sh ") else -1)
            for command in commands
        ]
        completed = subprocess.run(
            [str(harness_bin_dir() / "nas-secret-tx-harness")],
            input="\n".join(lines) + "\n",
            cwd=self.work,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        return Result(completed)

    def init(self, root: str = "root", stage: str = "stage", previous: str = "previous", *extra: str) -> str:
        return "\t".join(["init", self.p(root), self.p(stage), self.p(previous), *extra])

    def init_tx(self, tx: str = "tx") -> str:
        return "\t".join(["init", self.p("root"), self.p(f"{tx}/new"), self.p(f"{tx}/previous"), TARGET, self.p(tx)])

    def systemctl_log(self) -> str:
        log = self.work / "systemctl.log"
        return log.read_text(encoding="utf-8") if log.exists() else ""

    def started(self) -> bool:
        return any(line.startswith("start ") for line in self.systemctl_log().splitlines())

    def started_target(self) -> bool:
        return f"start {TARGET}" in self.systemctl_log().splitlines()

    def mv_count(self) -> int | None:
        count = self.work / "mv.count"
        return int(count.read_text()) if count.exists() else None


class SecretTransactionTests(unittest.TestCase):
    @contextlib.contextmanager
    def scenario(self, settings: dict[str, str] | None = None, *, privilege: str = "") -> Iterator[Scenario]:
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            (work / "root").mkdir()
            (work / "stage").mkdir()
            for path in (work / "root/ready", work / "root/old", work / "stage/ready", work / "stage/new"):
                path.touch()
            real_mv = shutil.which("mv") or "/bin/mv"
            real_rm = shutil.which("rm") or "/bin/rm"
            for name, body in (
                ("systemctl", SYSTEMCTL),
                ("mv", MV.replace("REAL_MV", real_mv)),
                ("rm", RM.replace("REAL_RM", real_rm)),
                ("priv", PRIV),
            ):
                shim = bin_dir / name
                shim.write_text(body, encoding="utf-8")
                shim.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{bin_dir}:{env.get('PATH', '')}",
                    "NAS_SECRET_TX_PRIVILEGE": str(bin_dir / privilege) if privilege else "",
                    "NAS_SECRET_TX_SYSTEMCTL": str(bin_dir / "systemctl"),
                    "NAS_TX_LOG": str(work / "systemctl.log"),
                    "NAS_TX_MV_COUNT": str(work / "mv.count"),
                    "NAS_TX_PRIV_LOG": str(work / "priv.log"),
                    "NAS_TX_INACTIVE_MARKER": str(work / "inactive-after-stop"),
                    "NAS_TX_OVERRIDES": str(work / "overrides.sh"),
                }
            )
            env.update(settings or {})
            yield Scenario(work, env)

    @staticmethod
    def parse(settings: str) -> dict[str, str]:
        return dict(item.split("=", 1) for item in settings.split())

    def make_tx(self, sc: Scenario, tx: str = "tx") -> None:
        shutil.copytree(sc.path("stage"), sc.path(f"{tx}/new"), symlinks=True)

    def test_unavailable_or_transitional_initial_observation_preserves_both_trees(self) -> None:
        for settings in (
            "NAS_TX_UNAVAILABLE=1",
            "NAS_TX_SHOW_FAIL=1",
            "NAS_TX_STATE=activating",
            "NAS_TX_STATE=deactivating",
            "NAS_TX_STATE=reloading",
            "NAS_TX_STATE=unknown",
            "NAS_TX_LOAD_STATE=not-found",
            "NAS_TX_STATE=inactive NAS_TX_JOB=42",
            "NAS_TX_JOB_MISSING=1",
        ):
            with self.subTest(settings=settings), self.scenario(self.parse(settings)) as sc:
                result = sc.run(sc.init(), "swap", "was-active", "cleanup 99")
                rc = result.status("swap")
                self.assertNotEqual(rc, 0)
                self.assertNotEqual(result.value("was-active"), "false")
                self.assertEqual(result.status("cleanup"), 125)
                self.assertTrue(sc.path("root/old").is_file() and sc.path("stage/new").is_file())
                self.assertFalse(sc.path("previous").exists())
                self.assertIsNone(sc.mv_count())
                self.assertIn("primary status 99", result.stderr)
                self.assertFalse(sc.started())

    def test_stop_must_be_observed_stable_even_if_stop_command_succeeds(self) -> None:
        for observation in (
            "NAS_TX_SHOW_FAIL=1",
            "NAS_TX_STATE=activating",
            "NAS_TX_STATE=deactivating",
            "NAS_TX_STATE=active",
            "NAS_TX_STATE=unknown",
            "NAS_TX_STATE=inactive NAS_TX_JOB=42",
            "NAS_TX_JOB_MISSING=1",
        ):
            for stop_rc in (0, 1):
                settings = {"NAS_TX_STOP_SETS": observation, "NAS_TX_STOP_RC": str(stop_rc)}
                with self.subTest(observation=observation, stop_rc=stop_rc), self.scenario(settings) as sc:
                    result = sc.run(sc.init(), "swap", "cleanup 83")
                    self.assertNotEqual(result.status("swap"), 0)
                    self.assertEqual(result.status("cleanup"), 125)
                    self.assertTrue(sc.path("root/old").is_file() and sc.path("stage/new").is_file())
                    self.assertFalse(sc.path("previous").exists())
                    self.assertIsNone(sc.mv_count())
                    self.assertIn("primary status 83", result.stderr)

    def test_observed_inactive_or_failed_target_allows_swap_without_restart_on_rollback(self) -> None:
        for stable_state in ("inactive", "failed"):
            settings = {"NAS_TX_STATE": stable_state, "NAS_TX_ACTIVE": "0", "NAS_TX_STOP_FAIL": "1"}
            with self.subTest(state=stable_state), self.scenario(settings) as sc:
                result = sc.run(sc.init(), "swap", "was-active", "sh test -f root/new -a -f previous/old", "cleanup 79")
                self.assertEqual(result.status("swap"), 0, result.stderr)
                self.assertEqual(result.value("was-active"), "false")
                self.assertEqual(result.status("sh"), 0)
                self.assertEqual(result.status("cleanup"), 79)
                self.assertTrue(sc.path("root/old").is_file())
                self.assertFalse(sc.path("previous").exists())
                self.assertFalse(sc.started())

    def test_rollback_stop_failure_preserves_live_previous_and_staged_recovery_material(self) -> None:
        for settings in (
            "NAS_TX_UNAVAILABLE=1",
            "NAS_TX_SHOW_FAIL=1",
            "NAS_TX_STATE=activating",
            "NAS_TX_STATE=deactivating",
            "NAS_TX_STATE=active",
            "NAS_TX_STATE=inactive NAS_TX_JOB=42",
            "NAS_TX_JOB_MISSING=1",
        ):
            with self.subTest(settings=settings), self.scenario() as sc:
                self.make_tx(sc)
                late = [f"setenv {key} {value}" for key, value in self.parse(settings).items()]
                result = sc.run(
                    sc.init_tx(),
                    "swap",
                    "sh mkdir tx/new && touch tx/new/partial",
                    "setenv NAS_TX_STOP_FAIL 1",
                    *late,
                    "cleanup 71",
                    "phase",
                )
                self.assertEqual(result.status("swap"), 0, result.stderr)
                self.assertEqual(result.status("cleanup"), 125)
                self.assertEqual(result.value("phase"), "rollback-incomplete")
                for path in ("root/new", "root/ready", "tx/previous/old", "tx/previous/ready", "tx/new/partial"):
                    self.assertTrue(sc.path(path).is_file(), path)
                self.assertEqual(sc.mv_count(), 2)
                self.assertIn(sc.p("tx/previous"), result.stderr)
                self.assertIn(sc.p("tx/new"), result.stderr)
                self.assertIn("primary status 71", result.stderr)
                self.assertFalse(sc.started())

    def test_rollback_restores_previous_tree_without_sudo(self) -> None:
        with self.scenario() as sc:
            result = sc.run(sc.init(), "swap", "cleanup 71")
            self.assertEqual(result.status("cleanup"), 71, result.stderr)
            self.assertTrue(sc.path("root/old").is_file())
            self.assertFalse(sc.path("root/new").exists())
            self.assertTrue(sc.started_target())
            self.assertNotIn("sudo", result.stderr)

    def test_pre_swap_failure_does_not_touch_active_target(self) -> None:
        with self.scenario() as sc:
            result = sc.run(sc.init(), "cleanup 77")
            self.assertEqual(result.status("cleanup"), 77)
            self.assertTrue(sc.path("root/old").is_file() and sc.path("root/ready").is_file())
            self.assertEqual(sc.systemctl_log(), "")

    def test_failed_pre_swap_cleanup_reports_retained_stage_and_recovery_tree(self) -> None:
        with self.scenario() as sc:
            self.make_tx(sc)
            result = sc.run(sc.init_tx(), f"setenv NAS_TX_RM_FAIL_PATH {sc.p('tx/new')}", "cleanup 78", "phase")
            self.assertEqual(result.status("cleanup"), 125)
            self.assertEqual(result.value("phase"), "rollback-incomplete")
            self.assertTrue(sc.path("root/old").is_file() and sc.path("root/ready").is_file())
            self.assertTrue(sc.path("tx/new/new").is_file())
            self.assertIn(
                f"nas-secret-transaction: pre-swap cleanup was incomplete; retained recovery tree {sc.p('tx')}; staged tree {sc.p('tx/new')}",
                result.stderr.splitlines(),
            )
            self.assertEqual(sc.systemctl_log(), "")

    def test_failed_restart_reports_incomplete_rollback(self) -> None:
        with self.scenario({"NAS_TX_START_FAIL": "1"}) as sc:
            result = sc.run(sc.init(), "swap", "cleanup 78")
            self.assertEqual(result.status("cleanup"), 125)
            self.assertTrue(sc.path("root/old").is_file())
            self.assertFalse(sc.path("root/new").exists())

    def test_commit_keeps_staged_tree_and_rejects_double_commit(self) -> None:
        with self.scenario() as sc:
            result = sc.run(sc.init(), "commit", "swap", "commit", "commit", "phase")
            self.assertEqual([result.status("commit", i) for i in range(3)], [1, 0, 1])
            self.assertTrue(sc.path("root/new").is_file())
            self.assertFalse(sc.path("root/old").exists() or sc.path("previous").exists())
            self.assertEqual(result.value("phase"), "committed")

    def test_double_swap_is_rejected_and_cleanup_restores_old_tree(self) -> None:
        with self.scenario() as sc:
            result = sc.run(sc.init(), "swap", "swap", "sh test -f root/new -a -f previous/old", "cleanup 79")
            self.assertEqual([result.status("swap", 0), result.status("swap", 1)], [0, 1])
            self.assertEqual(result.status("sh"), 0)
            self.assertEqual(result.status("cleanup"), 79)
            self.assertTrue(sc.path("root/old").is_file())
            self.assertFalse(sc.path("root/new").exists())

    def test_missing_previous_tree_is_manual_recovery_not_false_success(self) -> None:
        with self.scenario() as sc:
            result = sc.run(sc.init(), "swap", "sh rm -rf previous", "cleanup 80")
            self.assertEqual(result.status("cleanup"), 125)
            self.assertFalse(sc.path("root/new").exists())
            self.assertFalse(sc.started_target())

    def test_missing_ready_marker_prevents_restart(self) -> None:
        with self.scenario() as sc:
            result = sc.run(sc.init(), "swap", "sh rm -f previous/ready", "cleanup 81")
            self.assertEqual(result.status("cleanup"), 125)
            self.assertTrue(sc.path("root/old").is_file())
            self.assertFalse(sc.started_target())

    def test_symlinked_stage_and_live_root_are_rejected_before_stop(self) -> None:
        for kind in ("stage", "root"):
            with self.subTest(kind=kind), self.scenario() as sc:
                outside = sc.path("outside")
                outside.mkdir()
                (outside / ("new" if kind == "stage" else "old")).touch()
                (outside / "ready").touch()
                shutil.rmtree(sc.path(kind))
                sc.path(kind).symlink_to(outside)
                result = sc.run(sc.init(), "swap")
                self.assertNotEqual(result.status("swap"), 0)
                self.assertTrue((outside / ("new" if kind == "stage" else "old")).is_file())
                self.assertEqual(sc.systemctl_log(), "")

    def test_symlinked_parent_and_transaction_directory_are_rejected(self) -> None:
        with self.scenario() as sc:
            sc.path("real-parent/new").mkdir(parents=True)
            for name in ("new", "ready"):
                shutil.copy(sc.path(f"stage/{name}"), sc.path(f"real-parent/new/{name}"))
            sc.path("linked-parent").symlink_to(sc.path("real-parent"))
            result = sc.run(sc.init("root", "linked-parent/new", "linked-parent/previous"))
            self.assertEqual(result.status("init"), 1)
            self.assertTrue(sc.path("real-parent/new/new").is_file())
            self.assertEqual(sc.systemctl_log(), "")
        with self.scenario() as sc:
            sc.path("real-tx/new").mkdir(parents=True)
            for name in ("new", "ready"):
                shutil.copy(sc.path(f"stage/{name}"), sc.path(f"real-tx/new/{name}"))
            sc.path("tx-link").symlink_to(sc.path("real-tx"))
            result = sc.run(sc.init_tx("tx-link"))
            self.assertEqual(result.status("init"), 1)
            self.assertTrue(sc.path("real-tx/new/new").is_file())
            self.assertEqual(sc.systemctl_log(), "")

    def test_missing_stage_and_preexisting_previous_reject_before_stop(self) -> None:
        with self.scenario() as sc:
            shutil.rmtree(sc.path("stage"))
            result = sc.run(sc.init(), "swap")
            self.assertNotEqual(result.status("swap"), 0)
            self.assertTrue(sc.path("root/old").is_file())
            self.assertEqual(sc.systemctl_log(), "")
        with self.scenario() as sc:
            sc.path("previous").mkdir()
            sc.path("previous/stale").touch()
            result = sc.run(sc.init(), "swap")
            self.assertNotEqual(result.status("swap"), 0)
            self.assertTrue(sc.path("root/old").is_file() and sc.path("stage/new").is_file())
            self.assertTrue(sc.path("previous/stale").is_file())
            self.assertEqual(sc.systemctl_log(), "")

    def test_absolute_disjoint_paths_are_required(self) -> None:
        with self.scenario() as sc:
            result = sc.run(
                f"init\troot\t{sc.p('stage')}\t{sc.p('previous')}",
                sc.init("root", "root/child", "previous"),
                sc.init("root", "stage", "stage/previous"),
                f"init\t/\t{sc.p('stage')}\t{sc.p('previous')}",
            )
            self.assertEqual([result.status("init", i) for i in range(4)], [1, 1, 1, 1])
            self.assertTrue(sc.path("root/old").is_file() and sc.path("stage/new").is_file())

    def test_transaction_directory_policy_and_cleanup(self) -> None:
        with self.scenario() as sc:
            sc.path("tx/new").mkdir(parents=True)
            for name in ("new", "ready"):
                shutil.copy(sc.path(f"stage/{name}"), sc.path(f"tx/new/{name}"))
            shutil.rmtree(sc.path("stage"))
            bad = "\t".join(["init", sc.p("root"), sc.p("tx/new"), sc.p("tx/previous"), TARGET, sc.p("root/tx")])
            result = sc.run(bad, sc.init_tx(), "swap", "commit")
            self.assertEqual([result.status("init", 0), result.status("init", 1)], [1, 0])
            self.assertEqual(result.status("commit"), 0, result.stderr)
            self.assertTrue(sc.path("root/new").is_file())
            self.assertFalse(sc.path("tx").exists())

    def test_transaction_directory_validation_observes_privileged_filesystem(self) -> None:
        # Activation stages secrets under a root-owned 0700 transaction directory the
        # administrator cannot traverse, so physical checks must run through the
        # privilege wrapper; without elevation the layout is rejected.
        for elevate in ("0", "1"):
            with self.subTest(elevate=elevate), self.scenario({"NAS_TX_SIM_ELEVATE": elevate}, privilege="priv") as sc:
                sc.path("tx/transaction.1/new").mkdir(parents=True)
                sc.path("tx/transaction.1/previous").mkdir()
                result = sc.run(sc.init_tx("tx/transaction.1"))
                self.assertEqual(result.status("init"), 0 if elevate == "1" else 1, result.stderr)
                self.assertTrue(sc.path("root/old").is_file() and sc.path("stage/new").is_file())
                if elevate == "1":
                    self.assertTrue(sc.path("priv.log").read_text())

    def test_invalid_or_option_like_systemd_targets_are_rejected(self) -> None:
        # A newline-bearing target is covered by the Zig unit tests: the line
        # protocol of the harness cannot carry one.
        with self.scenario() as sc:
            result = sc.run(
                sc.init("root", "stage", "previous", "--root=/tmp.target"),
                sc.init("root", "stage", "previous", "bad.service"),
                sc.init("root", "stage", "previous", "bad.target;next"),
            )
            self.assertEqual([result.status("init", i) for i in range(3)], [1, 1, 1])
            self.assertEqual(sc.systemctl_log(), "")

    def test_cleanup_rejects_non_exit_status_values(self) -> None:
        with self.scenario() as sc:
            result = sc.run(sc.init(), "cleanup nope", "cleanup 256")
            self.assertEqual([result.status("cleanup", 0), result.status("cleanup", 1)], [125, 125])
            self.assertTrue(sc.path("root/old").is_file() and sc.path("stage/new").is_file())

    def test_inactive_system_without_prior_root_rolls_back_to_no_root(self) -> None:
        with self.scenario({"NAS_TX_ACTIVE": "0"}) as sc:
            shutil.rmtree(sc.path("root"))
            result = sc.run(sc.init(), "swap", "cleanup 82")
            self.assertEqual(result.status("cleanup"), 82, result.stderr)
            self.assertFalse(sc.path("root").exists() or sc.path("previous").exists())
            self.assertFalse(sc.started())

    def test_stop_failure_is_reported_and_cleanup_does_not_swap_files(self) -> None:
        with self.scenario({"NAS_TX_STOP_FAIL": "1"}) as sc:
            result = sc.run(sc.init(), "swap", "cleanup 83")
            self.assertNotEqual(result.status("swap"), 0)
            self.assertEqual(result.status("cleanup"), 125)
            self.assertTrue(sc.path("root/old").is_file())
            self.assertFalse(sc.path("root/new").exists() or sc.path("previous").exists())

    def test_nonzero_stop_is_accepted_only_when_target_became_inactive(self) -> None:
        with self.scenario({"NAS_TX_STOP_FAIL": "1", "NAS_TX_STOP_LEFT_INACTIVE": "1"}) as sc:
            result = sc.run(sc.init(), "swap")
            self.assertEqual(result.status("swap"), 0, result.stderr)
            self.assertTrue(sc.path("root/new").is_file() and sc.path("previous/old").is_file())
            self.assertIn(
                f"show --all --property=LoadState --property=ActiveState --property=Job {TARGET}",
                sc.systemctl_log().splitlines(),
            )

    def test_first_move_failure_preserves_old_tree_and_restarts_consumers(self) -> None:
        with self.scenario({"NAS_TX_MV_FAIL_AT": "1"}) as sc:
            result = sc.run(sc.init(), "swap", "cleanup 84")
            self.assertNotEqual(result.status("swap"), 0)
            self.assertEqual(result.status("cleanup"), 84, result.stderr)
            self.assertTrue(sc.path("root/old").is_file())
            self.assertFalse(sc.path("previous").exists() or sc.path("stage").exists())
            self.assertTrue(sc.started_target())

    def test_second_move_failure_restores_previous_tree(self) -> None:
        with self.scenario({"NAS_TX_MV_FAIL_AT": "2"}) as sc:
            result = sc.run(sc.init(), "swap", "cleanup 85")
            self.assertNotEqual(result.status("swap"), 0)
            self.assertEqual(result.status("cleanup"), 85, result.stderr)
            self.assertTrue(sc.path("root/old").is_file())
            self.assertFalse(sc.path("root/new").exists() or sc.path("previous").exists())
            self.assertTrue(sc.started_target())

    def test_failed_restore_preserves_previous_tree_and_reports_recovery_path(self) -> None:
        with self.scenario({"NAS_TX_MV_FAIL_AT": "3"}) as sc:
            self.make_tx(sc)
            result = sc.run(sc.init_tx(), "swap", "cleanup 86")
            self.assertEqual(result.status("cleanup"), 125)
            self.assertTrue(sc.path("tx/previous/old").is_file())
            self.assertFalse(sc.path("root").exists())
            lines = result.stderr.splitlines()
            self.assertIn(f"nas-secret-transaction: retained recovery tree {sc.p('tx')}", lines)
            self.assertIn(f"nas-secret-transaction: retained recovery tree {sc.p('tx/previous')}", lines)
            self.assertFalse(sc.started())

    def test_failed_live_tree_removal_cannot_nest_previous_or_restart_new_consumers(self) -> None:
        with self.scenario() as sc:
            self.make_tx(sc)
            result = sc.run(sc.init_tx(), "swap", f"setenv NAS_TX_RM_FAIL_PATH {sc.p('root')}", "cleanup 87")
            self.assertEqual(result.status("cleanup"), 125)
            self.assertTrue(sc.path("tx/previous/old").is_file() and sc.path("root/new").is_file())
            self.assertFalse(sc.path("root/previous").exists())
            self.assertFalse(sc.started())

    def test_stage_cleanup_failure_restarts_safely_restored_consumers(self) -> None:
        with self.scenario({"NAS_TX_MV_FAIL_AT": "2"}) as sc:
            result = sc.run(sc.init(), "swap", f"setenv NAS_TX_RM_FAIL_PATH {sc.p('stage')}", "cleanup 88", "phase")
            self.assertEqual(result.status("swap"), 74)
            self.assertEqual(result.status("cleanup"), 125)
            self.assertEqual(result.value("phase"), "rollback-incomplete")
            self.assertTrue(
                sc.path("root/old").is_file() and sc.path("root/ready").is_file() and sc.path("stage/new").is_file()
            )
            self.assertFalse(sc.path("previous").exists())
            self.assertTrue(sc.started_target())
            self.assertIn(sc.p("stage"), result.stderr)

    def test_stage_cleanup_without_a_prior_tree_reports_the_remaining_stage(self) -> None:
        with self.scenario({"NAS_TX_ACTIVE": "0", "NAS_TX_MV_FAIL_AT": "1"}) as sc:
            shutil.rmtree(sc.path("root"))
            result = sc.run(sc.init(), "swap", f"setenv NAS_TX_RM_FAIL_PATH {sc.p('stage')}", "cleanup 89")
            self.assertEqual(result.status("swap"), 74)
            self.assertEqual(result.status("cleanup"), 125)
            self.assertTrue(sc.path("stage/new").is_file())
            self.assertFalse(sc.path("root").exists() or sc.path("previous").exists())
            self.assertFalse(sc.started())
            self.assertIn(sc.p("stage"), result.stderr)


if __name__ == "__main__":
    unittest.main()
