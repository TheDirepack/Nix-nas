"""Cockpit protected-restart action against the real appliance flock.

The systemd worker is executed from the unit's own ExecStart in a clean
environment, matching systemd: no coordination token is inherited from the
Cockpit API process.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_cockpit_api as api  # noqa: E402
import nas_operation_lock as locks  # noqa: E402
from nas_common import CommandResult  # noqa: E402

UNIT_SOURCE = ROOT / "modules" / "nas" / "config" / "systemd-services.nix"
OPERATION_RUN = "${nasPythonApplication}/bin/nas-operation-run"
SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
START_COMMAND = ("systemctl", "start", "nas-protected-restart.service")

FAKE_SYSTEMCTL = textwrap.dedent(
    """
    import json, os, subprocess, sys
    record = {"argv": sys.argv[1:], "tokenPresent": bool(os.environ.get("NAS_OPERATION_COORDINATION_TOKEN"))}
    lock = [sys.executable, os.environ["NAS_TEST_LOCK_MODULE"]]
    record["validate"] = subprocess.run(
        [*lock, "--validate-current", "--class", "identity", "--class", "runtime"],
        capture_output=True, text=True, check=False,
    ).returncode
    contender_env = {k: v for k, v in os.environ.items() if k != "NAS_OPERATION_COORDINATION_TOKEN"}
    contender = subprocess.run(
        [*lock, "--action", "managed-service-policy", "--class", "runtime", "--", sys.executable, "-c", "pass"],
        env=contender_env, capture_output=True, text=True, check=False,
    )
    record["contender"] = {"returncode": contender.returncode, "stderr": contender.stderr}
    record["metadata"] = json.loads(open(os.environ["NAS_TEST_LOCK_FILE"], encoding="utf-8").read())
    with open(os.environ["NAS_TEST_SYSTEMCTL_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps(record) + "\\n")
    """
)

HOLDER = textwrap.dedent(
    """
    import sys
    sys.path.insert(0, sys.argv[1])
    import nas_operation_lock as locks
    with locks.acquire_operation("state-restore", ("appliance",)):
        print("held", flush=True)
        sys.stdin.read()
    """
)


def unit_exec_start() -> list[str]:
    source = UNIT_SOURCE.read_text(encoding="utf-8")
    block = re.search(r"\n    nas-protected-restart = \{\n(?P<body>.*?)\n    \};\n", source, re.S)
    if block is None:
        raise AssertionError("nas-protected-restart unit is missing")
    match = re.search(r'ExecStart = "(?P<command>[^"]+)";', block.group("body"))
    if match is None:
        raise AssertionError("nas-protected-restart ExecStart is missing")
    return shlex.split(match.group("command"))


class ProtectedRestartActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.tmp.name)
        self.root = base / "operations"
        self.root.mkdir(mode=0o770)
        os.chmod(self.root, 0o2770)
        self.lock_file = self.root / locks.LOCK_PATH_NAME
        self.log = base / "systemctl.jsonl"
        self.fake_systemctl = base / "fake_systemctl.py"
        self.fake_systemctl.write_text(FAKE_SYSTEMCTL, encoding="utf-8")
        self.worker_results: list[CommandResult] = []
        self.before_worker = None
        patches = [
            mock.patch.object(locks, "OPERATION_ROOT", self.root),
            mock.patch.dict(os.environ, {"NAS_STATE_ALLOW_UNPRIVILEGED": "1"}, clear=False),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        os.environ.pop(locks.COORDINATION_TOKEN_ENV, None)
        self.addCleanup(os.environ.pop, locks.COORDINATION_TOKEN_ENV, None)
        self.addCleanup(self.tmp.cleanup)

    def worker_argv(self) -> list[str]:
        argv: list[str] = []
        for part in unit_exec_start():
            if part == OPERATION_RUN:
                argv.extend([sys.executable, str(SERVICES / "nas_operation_lock.py")])
            elif part == SYSTEMCTL:
                argv.extend([sys.executable, str(self.fake_systemctl)])
            else:
                argv.append(part)
        return argv

    def clean_unit_environment(self) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "NAS_OPERATION_ROOT": str(self.root),
            "NAS_STATE_ALLOW_UNPRIVILEGED": "1",
            "NAS_TEST_LOCK_MODULE": str(SERVICES / "nas_operation_lock.py"),
            "NAS_TEST_LOCK_FILE": str(self.lock_file),
            "NAS_TEST_SYSTEMCTL_LOG": str(self.log),
        }

    def systemd_start(self, command, *, check: bool = True, timeout_seconds: int = 60, **_kwargs) -> CommandResult:
        """Model ``systemctl start`` of the oneshot unit: block until its worker exits."""
        self.assertEqual(tuple(command), START_COMMAND)
        self.assertFalse(check)
        if self.before_worker is not None:
            self.before_worker()
        completed = subprocess.run(
            self.worker_argv(),
            env=self.clean_unit_environment(),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
        result = CommandResult(completed.returncode, completed.stdout, completed.stderr)
        self.worker_results.append(result)
        return result

    def systemctl_calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def start_holder(self) -> subprocess.Popen[str]:
        holder = subprocess.Popen(
            [sys.executable, "-c", HOLDER, str(SERVICES)],
            env=self.clean_unit_environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.stop_holder, holder)
        assert holder.stdout is not None
        self.assertEqual(holder.stdout.readline().strip(), "held")
        return holder

    @staticmethod
    def stop_holder(holder: subprocess.Popen[str]) -> None:
        assert holder.stdin is not None and holder.stdout is not None
        if holder.poll() is None:
            holder.stdin.close()
            holder.wait(timeout=10)
        holder.stdout.close()

    def test_worker_owns_the_lock_for_the_whole_restart(self) -> None:
        with mock.patch.object(api, "run", side_effect=self.systemd_start), mock.patch.object(api, "diagnostic"):
            result = api.run_action("protected-restart")

        self.assertTrue(result["ok"])
        self.assertEqual(result["commands"][0]["command"], list(START_COMMAND))
        self.assertEqual([item.returncode for item in self.worker_results], [0])
        calls = self.systemctl_calls()
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(call["argv"], ["restart", "nas-protected-services.target"])
        self.assertTrue(call["tokenPresent"])
        self.assertEqual(call["validate"], 0)
        self.assertEqual(call["metadata"]["action"], "protected-restart")
        self.assertEqual(call["metadata"]["classes"], ["identity", "runtime"])
        self.assertEqual(call["contender"]["returncode"], 75)
        self.assertIn("conflicts with managed-service-policy", call["contender"]["stderr"])
        self.assertEqual(locks.operation_state()["busyClasses"], [])

    def test_conflicting_operation_is_refused_before_the_unit_starts(self) -> None:
        self.start_holder()
        with (
            mock.patch.object(api, "run", side_effect=self.systemd_start) as run,
            mock.patch.object(api, "diagnostic"),
        ):
            with self.assertRaisesRegex(api.ApiError, "Another privileged operation conflicts with protected-restart"):
                api.run_action("protected-restart")
        run.assert_not_called()
        self.assertEqual(self.systemctl_calls(), [])

    def test_operation_that_wins_the_launch_race_blocks_the_restart(self) -> None:
        holders: list[subprocess.Popen[str]] = []
        self.before_worker = lambda: holders.append(self.start_holder())
        with (
            mock.patch.object(api, "run", side_effect=self.systemd_start),
            mock.patch.object(api, "diagnostic") as diagnostic,
        ):
            with self.assertRaisesRegex(api.ApiError, "Operation failed"):
                api.run_action("protected-restart")
        self.assertEqual([item.returncode for item in self.worker_results], [75])
        self.assertIn("conflicts with protected-restart", self.worker_results[0].stderr)
        self.assertEqual(self.systemctl_calls(), [])
        self.assertIn("nas-protected-restart.service", diagnostic.call_args.args[0])
        self.assertEqual(len(holders), 1)
        self.assertEqual(locks.operation_state()["active"][0]["action"], "state-restore")

    def test_api_caller_does_not_inherit_or_publish_a_coordination_token(self) -> None:
        observed: list[dict] = []

        def record_start(command, **kwargs) -> CommandResult:
            observed.append({"state": locks.operation_state(), "token": os.environ.get(locks.COORDINATION_TOKEN_ENV)})
            return self.systemd_start(command, **kwargs)

        with mock.patch.object(api, "run", side_effect=record_start), mock.patch.object(api, "diagnostic"):
            api.run_action("protected-restart")
        self.assertEqual(len(observed), 1)
        self.assertIsNone(observed[0]["token"])
        self.assertEqual(observed[0]["state"]["busyClasses"], [])
        self.assertEqual(observed[0]["state"]["active"], [])


class CockpitBridgeSandboxTests(unittest.TestCase):
    def test_gui_bridge_can_open_the_operation_lock(self) -> None:
        source = (ROOT / "modules" / "nas" / "config" / "application-services.nix").read_text(encoding="utf-8")
        block = re.search(r"\n    systemd\.services\.nas-cockpit-sso = \{\n(?P<body>.*?)\n    \};\n", source, re.S)
        self.assertIsNotNone(block)
        assert block is not None
        body = block.group("body")
        self.assertIn('ProtectSystem = "strict";', body)
        write_paths = re.search(r"ReadWritePaths = \[(?P<paths>[^\]]*)\];", body)
        self.assertIsNotNone(write_paths)
        assert write_paths is not None
        self.assertIn('"/run/nas-operations"', write_paths.group("paths").split())
        system = (ROOT / "modules" / "nas" / "config" / "system.nix").read_text(encoding="utf-8")
        self.assertIn('"d /run/nas-operations 2770 root nas-operations -"', system)
        gui_api = (ROOT / "cockpit" / "src" / "api.js").read_text(encoding="utf-8")
        self.assertRegex(gui_api, r'spawn\)\(\["nas-cockpit-api", \.\.\.args\], \{\n\s+superuser: "require",')


if __name__ == "__main__":
    unittest.main()
