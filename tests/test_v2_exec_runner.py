from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_exec_runner as runner  # noqa: E402


class V2ExecRunnerTests(unittest.TestCase):
    def test_descriptor_is_execve_argv_not_shell_text(self):
        descriptor = {
            "command": ["/bin/echo", "hello; touch /tmp/not-a-shell"],
            "workingDirectory": "/tmp",
            "environment": {"DEMO": "value with spaces"},
        }
        with (
            mock.patch.object(runner.os, "chdir") as chdir,
            mock.patch.object(runner.os, "execve") as execve,
            mock.patch.dict(runner.os.environ, {"BASE": "1"}, clear=True),
        ):
            runner.run_descriptor(descriptor)
        chdir.assert_called_once_with("/tmp")
        argv = execve.call_args.args[1]
        environment = execve.call_args.args[2]
        self.assertEqual(argv, descriptor["command"])
        self.assertEqual(environment["BASE"], "1")
        self.assertEqual(environment["DEMO"], "value with spaces")

    def test_relative_executable_is_rejected(self):
        with self.assertRaisesRegex(runner.ExecRunnerError, "absolute"):
            runner.validate_descriptor({"command": ["echo", "hello"]})

    def test_invalid_environment_name_is_rejected(self):
        with self.assertRaisesRegex(runner.ExecRunnerError, "environment variable"):
            runner.validate_descriptor({"command": ["/bin/true"], "environment": {"BAD=NAME": "x"}})


if __name__ == "__main__":
    unittest.main()
